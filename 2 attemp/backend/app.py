from flask import Flask, render_template, url_for, redirect,request,flash,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import csv
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
import re
from sklearn.metrics.pairwise import cosine_similarity


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.app_context().push()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Password"})
    
    confirm = PasswordField(validators=[
                             InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Confirm Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')




class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')



class Artwork(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    artistName = db.Column(db.String(80), nullable=False)
    image = db.Column(db.String(300), nullable=False)




class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    artwork_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    favorite = db.Column(db.Boolean, default=False, nullable=False)



with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    artworks = db.session.query(Artwork).limit(30).all()
    return render_template('dashboard.html',artworks=artworks)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit() :
        if form.password.data==form.confirm.data:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/artworks/<int:artwork_id>')
def artwork_detail(artwork_id):
    artwork = Artwork.query.get_or_404(artwork_id)
    favorite_status = False
    print(current_user)
    if current_user.is_authenticated:
        favorite = Favorite.query.filter_by(user_id=current_user.id, artwork_id=artwork_id).first()
        if favorite:
            favorite_status = True
    else:
        flash('Please log in to add this artwork to your favorites!', 'warning')
    return render_template('artwork_detail.html', artwork=artwork, favorite_status=favorite_status)





@app.route('/toggle_favorite/<int:artwork_id>', methods=['GET', 'POST'])
@login_required
def toggle_favorite(artwork_id):
    artwork = Artwork.query.get(artwork_id)
    if not artwork:
        flash('artwork doesn\'t exist')
        return redirect(url_for('artworks'))
    
    favorite = Favorite.query.filter_by(user_id=current_user.id, artwork_id=artwork_id).first()
    
    if request.method == 'POST':
        if not favorite:
            favorite = Favorite(user_id=current_user.id, artwork_id=artwork_id, favorite=True)
            db.session.add(favorite)
            db.session.commit()
            return jsonify({'status': 'favorited'})
        else:
            db.session.delete(favorite)
            db.session.commit()
            return jsonify({'status': 'unfavorited'})
    elif request.method == 'GET':
        if not favorite:
            return jsonify({'status': 'unfavorited'})
        else:
            return jsonify({'status': 'favorited'})



@app.route('/favorite')
@login_required
def favorite():
    favorites = (
        db.session.query(Favorite, Artwork)
        .join(Artwork, Favorite.artwork_id == Artwork.id)
        .filter(Favorite.user_id == current_user.id, Favorite.favorite == True)
        .all()
    )
    return render_template('favorite.html', favorites=favorites)


df=pd.read_csv('mydata8.csv')
df.dropna(subset=['genres','styles'], inplace=True)
new_df = df[df['genres'] != '[]'].copy()
df=new_df
new_df = df[df['styles'] != '[]'].copy()
df=new_df

pattern = r"'(.*?)'"

# Combine all features into one text column
df['text'] = df['title'] + ' ' + df['artistName'] + ' ' + df['genres'].apply(lambda x: re.findall(pattern, x)[0]) + ' ' + df['styles'].apply(lambda x: re.findall(pattern, x)[0])

# Fit and transform the TfidfVectorizer to create feature vectors
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df['text'])

# Calculate cosine similarity between all pairs of artworks
cosine_sim = cosine_similarity(X)

# your recommendation system function
def get_recommendations(index, cosine_sim=cosine_sim):

    index = int(index)
    # Get similarity scores for all artworks
    sim_scores = list(enumerate(cosine_sim[index]))
    
    # Sort the artworks based on the similarity scores
    sim_scores = sorted(sim_scores, key=lambda x: x[1], reverse=True)
    
    # Get the top 5 most similar artworks (excluding the artwork itself)
    top_artwork_indices = [i for i, s in sim_scores[1:6]]
    
    return top_artwork_indices


@app.route('/recommendations/<preferred_artwork_id>')
def recommendations(preferred_artwork_id):
    recommended_artwork_indices = get_recommendations(preferred_artwork_id)
    recommended_artworks = []
    for index in recommended_artwork_indices:
        artwork = {}
        artwork['title'] = df.loc[index, 'title']
        artwork['artistName'] = df.loc[index, 'artistName']
        artwork['genres'] = df.loc[index, 'genres']
        artwork['styles'] = df.loc[index, 'styles']
        artwork['tags'] = df.loc[index, 'tags']
        artwork['image'] = df.loc[index, 'image']
        artwork['description'] = df.loc[index, 'description']
        recommended_artworks.append(artwork)
    
    return render_template('recommendations.html', artworks=recommended_artworks)
















def import_csv_to_database(filename):
    with open(filename, 'r',encoding='utf-8') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            artwork = Artwork(
                # id=row['id'],
                title=row['title'],
                artistName=row['artistName'],
                image=row['image'],
                # description=row['description'],
                # completionYear=row['completitionYear']

            )
            db.session.add(artwork)
        db.session.commit()

@app.before_first_request
def import_data():
    # 如果数据库中没有任何数据，则导入 CSV 文件
    if not db.session.query(Artwork).count():
        import_csv_to_database('mydata8.csv')

if __name__ == "__main__":
    app.run(debug=True)
