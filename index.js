const express = require('express')
const sequelize  = require('./db')
const { DataTypes,Op } = require('sequelize')
const session = require('express-session')
const csrf = require('csurf');
const { isAuthenticated } = require('./middlewares/auth.middleware')

const app = express()
const port = 3000

app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: true }))
app.use(
    session({
        secret: 'secret',
        saveUninitialized: true,
        cookie: { maxAge: 3600000}
    })
)
const csrfProtection = csrf({ sessionKey: 'session' });

const User = sequelize.define(
    'User', {
        username: {
            type: DataTypes.STRING,
            unique: true,
            allowNull: false
        },
        email: {
            type: DataTypes.STRING,
            unique: true,
            allowNull: false
        },
        password: {
            type: DataTypes.STRING,
            allowNull: false
        }
    },
    {
        timestamps: true,
    }
);

sequelize.sync({force:false})
 .then(() => console.log('User table created successfully.'))
 .catch(err => console.error('Unable to create the User table:', err));

app.get('/', (req, res) => {
    if (req.session && req.session.email) {
        return res.redirect('/profile');
    }
    res.render('index');
})

app.get('/login', (req, res) => {
    if (req.session && req.session.email) {
        return res.redirect('/profile');
    }
    res.render('login');
})

app.post('/login', async(req, res) => {
    const { email, password } = req.body
    const exists_user = await User.findOne({ where: { email, password } })
    if (!exists_user) {
        res.send({ message: 'Invalid email or password'})
        return
    }
    if (password === exists_user.password) {
        req.session.email = email
        res.redirect('/profile')
    } else {
        res.send({ message: 'Invalid email or password'})
        return
    }
})

app.get('/signup', (req, res) => {
    if (req.session && req.session.email) {
        return res.redirect('/profile');
    }
    res.render('signup');
})

app.post('/signup', async(req, res) => {
    const { username, email, password } = req.body
    const exists_user = await User.findOne({
        where: {
            [Op.or]: [{ username }, { email }]
        }
    })
    if (exists_user) {
        res.send({ message: 'User or email already exists, please try again'})
        return
    }
    await User.create({ username, email, password })
    res.redirect('/login')
})

app.get('/profile', isAuthenticated, csrfProtection, async(req, res) => {
    const user = await User.findOne({
        where: {
             email: req.session.email 
        }
    })
    res.render('profile', {csrfToken: req.csrfToken(),username: user.username, email: user.email})
})

app.post('/update-profile', isAuthenticated, csrfProtection, async(req, res) => {
    const { email, username } = req.body
    if (username){
        await User.update({
            username,
           },
           {
            where: { email: req.session.email } 
           })
    }
    if (email){
        await User.update({
            email,
           },
           {
            where: { email: req.session.email } 
           })
        req.session.email = email
    }
    res.redirect('/profile')
})

app.post('/change-password', isAuthenticated, async(req, res) => {
    const { newPassword, confirmPassword } = req.body
    const referrer = req.get('Referer');

    const referrerRegex = /^http:\/\/localhost:\d+\/profile\/?$/;

    if (!referrer || !referrerRegex.test(referrer)) {
        return res.status(403).send('Access denied: Invalid referrer.');
    }

    if (newPassword === confirmPassword) {
        await User.update({
            password: newPassword 
            },
            {
            where: { email: req.session.email } 
            })
        res.redirect('/login')
        req.session.destroy()
    } else {
        res.status(400).send({ message: 'Passwords do not match, please try again'})
        return
    }
})

app.post('/logout', (req, res) => {
    req.session.destroy()
    res.redirect('/')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})