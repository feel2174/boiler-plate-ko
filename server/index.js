const express = require('express')
const app = express()
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { auth } = require('./middleware/auth');
const { User } = require('./models/User');
const config = require('./config/key');

//application/x-www-from-urlencoded
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(cookieParser());

const mongoose = require('mongoose')
mongoose.connect(config.mongoURI, {
    useNewUrlParser: true, useUnifiedTopology:true, useCreateIndex: true, useFindAndModify: false}).then(() => console.log('MongoDB connected...'))
.catch(err => console.log(err))

app.get('/', (req, res) => res.send('Hello World!'))

app.get('/api/hello', (req, res) => res.send('안녕하세여!!'))

app.post('/api/users/register', (req, res) => {
    //회원가입 할때 필요한 정보들을 client에서 가져오면
    //그것들을 DB엔 넣어준다.
    const user = new User(req.body)
    user.save((err, userInfo) => {
        if(err) return res.json({ suceess: false, err})
        return res.status(200).json({
            success: true
        })
    })
})

app.post('/api/users/login', (req, res) => {
    //요청된 이메일을 DB에서 검색한다.
    //요청된 이메일이 DB에 존재한다면, 비밀번호를 검증한다.
    //비밀번호가 일치한다면 토큰을 생성한다.

    User.findOne({ email: req.body.email }, (err, user) => {
        if(!user) {
            return res.json({
            loginSuccess: false,
            message: "이메일에 해당하는 유저가 없습니다."
            })
        }

        user.comparePassword(req.body.password, (err, isMatch) => {
            if (!isMatch)
            return res.json({ loginSuccess:false, message: "비밀번호가 틀렸습니다." })
            user.generateToken((err, user) => {
                if(err) return res.status(400).send(err); 
                res.cookie("x_auth", user.token)
                .status(200)
                .json({
                    loginSuccess: true,
                    userId: user._id
                })
                //토큰을 저장한다, where? 쿠키, 로컬스토리지
            })
        })
    })

})

app.get('/api/users/auth', auth , (req, res) => {
    res.status(200).json({
        _id: req.userId,
        isAdmin: req.user.role === 0 ? false : true,
        isAuth: true,
        email: req.user.email,
        name: req.user.name,
        lastname: req.user.lastname,
        role: req.user.role,
        image: req.user.image
    })
})

app.get('/api/users/logout', auth, (req, res) => {
    User.findOneAndUpdate({ _id: req.user._id },
        { token: "" }, (err, user) => {
            if(err) return res.json({ success: false, err})
            return res.status(200).send({
                success: true
            })
        })
})

const port = 5000
app.listen(port, () => console.log(`Example app listening at http://localhost:${port}`))