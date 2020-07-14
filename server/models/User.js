const mongoose = require('mongoose');
const bCrypt = require('bcrypt');
const saltRounds = 10
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
    name : {
        type: String,
        maxLength: 50
    },
    email: {
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        maxLength: 5
    },
    lastname: {
        type: String,
        maxLength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})


userSchema.pre('save', function( next ) {
    //비밀번호를 암호화합니다.
    var user = this;
    if(user.isModified('password')) {
        bCrypt.genSalt(saltRounds, function(err, salt) {
            if(err) return next(err)
    
            bCrypt.hash(user.password , salt , function(err, hash) {
                if(err) return next(err)
                user.password = hash
                next()
            } )
        })
    } else {
        next()
    }
    
})

userSchema.methods.comparePassword = function (plainPassword, cb) {
    bCrypt.compare(plainPassword, this.password, function (err, isMatch) {
        if(err) return cb(err);
        cb(null, isMatch)
    })
} 

userSchema.methods.generateToken = function(cb) {
    var user = this;
    // jwt로 토큰생성
    var token  = jwt.sign(user._id.toHexString(), 'secretToken')
    user.token = token
    user.save(function(err, user) {
        if(err) return cb(err)
        cb(null, user)
    })
}
userSchema.statics.findByToken = function(token, cb) {
    var user = this;
    jwt.verify(token, 'secretToken', function(err, decoded) {
        //유저 아이디를 이용해서 유저를 찾은 다음에
        //클라이언트에서 가져온 token과 DB의 Token이 일치하는지 확인

        user.findOne({"_id": decoded, "token": token}, function(err, user){
            if(err) return cb(err);
            cb(null, user)
        })
    })
}
const User = mongoose.model('User', userSchema)

module.exports = {User}