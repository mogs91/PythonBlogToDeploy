from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, InputRequired, Length
from flask_ckeditor import CKEditorField


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


##Registration Form
class RegistrationForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    email = StringField(label='email',
                        validators=[InputRequired()] )
    password = PasswordField(label='password',
                             validators=[InputRequired(), Length(8)])
    submit = SubmitField('Register User')


##Login Form
class LoginForm(FlaskForm):
    email = StringField(label='email',
                        validators=[DataRequired()])
    password = PasswordField(label='password',
                             validators=[DataRequired()])
    submit = SubmitField('Login')


##Comment Form
class CommentForm(FlaskForm):
    comment_field = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField('Submit')
