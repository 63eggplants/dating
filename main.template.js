const express = require('express');
const app = express();
const db = require('./lib/db.template');
const bodyParser = require('body-parser');
const compression = require('compression');
const helmet = require('helmet');
app.use(helmet());
const bcrypt = require('bcrypt');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const flash = require('connect-flash');

// body 데이터를 간편하게 추출
app.use(
  bodyParser.urlencoded({
    extended: false,
  })
);

// 정적 파일 로드
app.use(express.static('public'));

// 파일 압축 관련
app.use(compression());

// 세션 사용
app.use(
  session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
    store: new MySQLStore({
      host: '',
      user: '',
      password: '',
      database: '',
    }),
  })
);
app.use(flash());

// passport 관련
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

app.use(passport.initialize());
app.use(passport.session());

// root 화면
// login 전이라면 register, login, login with google을 보여주고
// login 후라면 로그인 이메일과 logout을 보여줌
app.get('/', (req, res) => {
  // req.user가 있다는 것은 로그인이 되어 있다는 의미
  if (req.user) {
    const fmsg = req.flash();
    let feedback = '';
    if (fmsg.success) {
      feedback = fmsg.success[0];
    }
    res.send(`
    <!DOCTYPE html>
  <html>
    <head>
      <meta charset="UTF-8" />
      <meta http-equiv="X-UA-Compatible" content="IE=edge" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>dating</title>
    </head>
    <body>
      <p style="color:blue;">${feedback}</p>
      ${req.user.email} | <a href="/auth/logout">logout</a>
    </body>
  </html>
    `);
  } else {
    res.send(`
    <!DOCTYPE html>
  <html>
    <head>
      <meta charset="UTF-8" />
      <meta http-equiv="X-UA-Compatible" content="IE=edge" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>dating</title>
    </head>
    <body>
      <a href="/auth/register">register</a>
      <a href="/auth/login">login</a>
      <a href="/auth/google">login with google</a>
    </body>
  </html>
    `);
  }
});

app.get('/auth/register', (req, res) => {
  const fmsg = req.flash();
  let feedback = '';
  if (fmsg.error) {
    feedback = fmsg.error[0];
  }

  res.send(`
  <!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>dating</title>
  </head>
  <body>
  <a href="/">home</a>
    <p style="color:red;">${feedback}</p>
    <form action="/auth/register_process" method="post">
      <p>
        <input type="text" name="email" placeholder="email" />
      </p>
      <p>
        <input type="password" name="pwd" placeholder="password" />
      </p>
      <p>
        <input type="password" name="pwd2" placeholder="password" />
      </p>
      <p>
        <button>register</button>
      </p>
    </form>
  </body>
</html>

  `);
});

app.post('/auth/register_process', (req, res) => {
  const post = req.body;
  const email = post.email;
  const pwd = post.pwd;
  const pwd2 = post.pwd2;
  if (email === '' || pwd === '' || pwd2 === '') {
    req.flash('error', 'Please fill in the required information');
    res.redirect('/auth/register');
  } else if (pwd !== pwd2) {
    req.flash('error', 'Password must be same');
    res.redirect('/auth/register');
  } else {
    bcrypt.hash(pwd, 10, (err, hash) => {
      db.query('select * from TestUser where email=?', [email], (err, user) => {
        if (err) {
          throw err;
        }
        if (user.length > 0) {
          if (user[0].password) {
            req.flash('error', 'Please fill another email');
            return res.redirect('/auth/register');
          } else {
            db.query(
              'update TestUser set password=? where email=?',
              [hash, email],
              (err2, result) => {
                req.session.save(() => {
                  req.login(user[0], err4 => {
                    return res.redirect('/');
                  });
                });
              }
            );
          }
        } else if (user.length === 0) {
          console.log('hi');
          db.query(
            'insert into TestUser(email, password) values(?, ?)',
            [email, hash],
            (err2, result) => {
              if (err2) {
                throw err2;
              }
              db.query(
                'select * from TestUser where email=?',
                [email],
                (err3, user) => {
                  req.session.save(() => {
                    req.login(user[0], err4 => {
                      req.flash('success', 'Welcome');
                      return res.redirect('/');
                    });
                  });
                }
              );
            }
          );
        }
      });
    });
  }
});

app.get('/auth/login', (req, res) => {
  const fmsg = req.flash();
  let feedback = '';
  if (fmsg.error) {
    feedback = fmsg.error[0];
  }
  res.send(`
  <!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>dating</title>
  </head>
  <body>
  <a href="/">home</a>
    <p style="color:red;">${feedback}</p>
    <form action="/auth/login_process" method="post">
      <p><input type="text" name="email" placeholder="email" /></p>
      <p><input type="password" name="pwd" placeholder="password" /></p>
      <p>
        <input type="submit" value="login" />
      </p>
    </form>
  </body>
</html>

  `);
});

app.post(
  '/auth/login_process',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/auth/login',
    failureFlash: true,
    successFlash: true,
  })
);

passport.serializeUser((user, done) => {
  // done()으로 또는 req.login()에서 전달한 user[0]이 serializeUser의 user로 들어오고 세션 스토어에 사용자의 식별자를 저장
  // 즉 serialzieUser는 로그인 시 단 한번만 실행되며 사용자의 식별자를 세션 스토어에 저장하기 위함
  // serializeUser의 done의 인자로 전달한 user.id가 세션 스토어에 저장되는 user의 정보
  console.log('serializeUser', user);
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  // 로그인 성공 후 매 페이지를 방문할 때마다 로그인한 사용자인지 체크를 해야하는데 이를 위해 desrializeUser 함수가 호출됨
  // 세션 스토어에 저장된 데이터 즉 serializeUser에서 저장한 user의 id 값을 이용해서 mysql에서 해당 user를 조회하고 그 user의 정보를 done()의 인자로 넘겨줌으로써 해당 user의 데이터가 req.user의 값으로 지정됨
  db.query('select * from TestUser where id=?', [id], (error, user) => {
    if (error) {
      throw error;
    }
    console.log(user[0]);
    done(null, user[0]);
  });
});

// local의 방식을 사용하겠다는 것
passport.use(
  new LocalStrategy(
    {
      // login 페이지에서 전달 받은 email, pwd에 대한 input value를 usernameField, passwordField로 설정
      usernameField: 'email', //
      passwordField: 'pwd',
    },
    (email, password, done) => {
      // 위에서 설정한대로 email, password에는 각각의 input value가 들어감
      db.query(
        'select * from TestUser where email=?',
        [email],
        (error, user) => {
          // 존재하는 user일 경우
          if (user.length === 1) {
            // bcrypt.compare 함수에 입력한 password와 db에 저장된 암호화된 password를 인자로 넘겨주고, 세번째 콜백함수에서 일치 여부를 result로 알려줌. 즉 result는 boolean 값
            bcrypt.compare(password, user[0].password, (error2, result) => {
              // 일치한다면 done()에 user 정보와 flash message를 전달함. 여기서 전달한 user정보가 serializeUser의 인자로 들어감
              if (result) {
                return done(null, user[0], {
                  message: 'Welcome',
                });
              } else {
                return done(null, false, {
                  message: 'Incorrect password',
                });
              }
            });
          }
          // 존재하지 않는 user일 경우
          else {
            return done(null, false, {
              message: 'Wrong email',
            });
          }
        }
      );
    }
  )
);

// goolge 로그인 방식 사용
const googleCredentials = require('./config/google.template.json');
passport.use(
  new GoogleStrategy(
    {
      clientID: googleCredentials.web.client_id,
      clientSecret: googleCredentials.web.client_secret,
      callbackURL: googleCredentials.web.redirect_uris[0],
    },
    (accessToken, refreshToken, profile, done) => {
      // 구글이 전달한 사용자 정보가 profile에 있음
      const email = profile.emails[0].value;
      db.query('select * from TestUser where email=?', [email], (err, user) => {
        if (err) {
          throw err;
        }
        // 만약 해당 이메일로 이미 사용자 정보가 있을 경우.
        if (user.length === 1) {
          // 이미 google 방식으로 가입한 경우 해당 user정보 찾아서 바로 serializeUser로 넘겨줌
          if (user[0].googleId) {
            db.query(
              'select * from TestUser where email=?',
              [email],
              (err2, user) => {
                done(null, user[0], {
                  message: 'Welcome',
                });
              }
            );
          }
          // 이미 local 방식으로 가입한 경우, 즉 googleId는 null로 되어 있음. 이 경우 해당 user 데이터에 googleId 정보를 추가 후 user 정보 전달함
          else {
            db.query(
              'update TestUser set googleId=? where id=?',
              [profile.id, user[0].id],
              (err2, result) => {
                if (err2) {
                  throw err2;
                }
                done(null, user[0], {
                  message: 'Welcome',
                });
              }
            );
          }
        }
        // 구글에서 전달한 이메일로 관련 user 없을 경우. 즉 local로 가입한 적도 없는 최초 가입
        else {
          db.query(
            'insert into TestUser(email, googleId) values(?, ?)',
            [email, profile.id],
            (err2, result) => {
              if (err2) throw err2;
              db.query(
                'select * from TestUser where email=?',
                [email],
                (err3, user) => {
                  if (err3) throw err3;
                  done(null, user[0], {
                    message: 'Welcome',
                  });
                }
              );
            }
          );
        }
      });
    }
  )
);

// /auth/goolge로 접속 시 passport의 google 로그인 방식을 사용하겠다는 의미
// scope은 사용 범위. 여기서는 로그인과 이메일
app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['https://www.googleapis.com/auth/plus.login', 'email'],
  })
);

// 구글이 resource owner 즉 우리 서비스를 가입할 회원에게 /auth/google/callback으로 redirect 시키고 이를 통해 우리 서비스는 google로부터 authorization code를 전달 받음. 이걸 받아서 passport.use(new google...)으로 감
app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/',
    successFlash: true,
  }),
  (req, res) => res.redirect('/')
);

// 로그아웃 시
app.get('/auth/logout', (req, res) => {
  req.logout();
  req.session.save(() => {
    res.redirect('/');
  });
});

app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});
