const { User } = require('../models/User');

let auth = (req, res, next) => {
        //인증 처리 담당
        //클라이언트 쿠키에서 토큰을 가져온다.
        let token = req.cookies.x_auth;

        //토큰 복호화 후 유저 검색
        User.findByToken(token, (err, user) => {
            if(err) throw err;
            if(!user) return res.json({ isAuth: false, error: true})

            req.token = token;
            req.user = user;
            next();

        })
        //유저 유무에 따라 인증!
}

module.exports = { auth };