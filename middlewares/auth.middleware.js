function isAuthenticated(req, res, next) {
    if (req.session.email) {
        return next();
    } else {
        return res.redirect('/login');
    }
}

module.exports = { isAuthenticated };