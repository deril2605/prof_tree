var express     = require("express"),
    app         = express(),
    bodyParser  = require("body-parser"),
    mongoose    = require("mongoose"),
    methodOverride = require("method-override"),
    passport    = require("passport"),
    LocalStrategy = require("passport-local"),
    passportLocalMongoose = require("passport-local-mongoose"),
    bcrypt      = require('bcryptjs'),
    expressValidator = require('express-validator'),
    multer = require('multer'),
    upload = multer({dest: './uploads'});
    
    
mongoose.connect("mongodb://localhost/proftree",{ useNewUrlParser: true });

//EXPERIENCE SCHEMA

var experienceSchema = new mongoose.Schema({
    projname: String,
    fromdate: String,
    todate: String,
    teachername: String,
    description: String
})

var Experience = mongoose.model("Experience", experienceSchema)

//STUDENT LIST SCHEMA

var studentListSchema = new mongoose.Schema({
    stufirstname: String,
    stulastname: String,
    sturoll: String,
    stuproj: String,
    stufromdate: String,
    stutodate: String,
    studescp: String
})

var StudentList = mongoose.model("StudentList", studentListSchema)

//STUDENT SCHEMA

var studentSchema = new mongoose.Schema({
   username: String,
   gender: String,
   //rollnumber: String,
   dob: String,
   email: String,
   phno: String,
   branch: String,
   gradyear: String,
   college: String,
   address: String,
   age: String,
   password: String,
   password1: String,
   type: String,
   firstName: String,
   lastName: String,
   exp: [experienceSchema]
});

var Student = mongoose.model("Student", studentSchema);

//TEACHER SCHEMA

var teacherSchema = new mongoose.Schema({
   username: String,
   designation: String,
   gender: String,
   dob: String,
   email: String,
   phno: String,
   qualification: String,
   interests: String,
   college: String,
   fields: String,
   address: String,
    password: String,
   password1: String,
   type: String,
   firstName: String,
   lastName: String,
   stu: [studentListSchema]
   //rollnumber: String
});

var Teacher = mongoose.model("Teacher", teacherSchema);

//REQUIREMENTS

app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");
app.use(express.static(__dirname + "/public"));
  /
app.use(expressValidator());
mongoose.set('useFindAndModify', false);

//PASSPORT REQUIREMENTS

app.use(require("express-session")({
    secret: "Rusty is the best and cutest dog in the world",
    resave: false,
    saveUninitialized: false
    
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(function(req, res, next){
    Teacher.find({}, function(err, teachers){
        if(err) throw err;
        else{
            res.locals.teachers = teachers
        }
    })
   //res.locals.currentUser = req.user;
   next();
});

//-----------
//AUTH ROUTES
//-----------

//REGISTER

app.get("/register", function(req, res){
    res.render("Sregister")
})

app.post("/register", function(req, res){
    var type = req.body.type
    if(type=="student"){
    var newUser = new Student({
        username: req.body.username,
        gender: req.body.gender,
        //rollnumber: req.body.rollnumber,
        dob: req.body.dob,
        email: req.body.email,
        type: req.body.type,
        password: req.body.password,
        firstName: req.body.firstName,
        lastName: req.body.lastName
    })
    console.log(req.body.username)
    
    req.checkBody('username','Roll Number/Institute ID is Required').notEmpty();
    req.checkBody('email','Email Required').notEmpty();
    req.checkBody('email','Email Invalid').isEmail();
    req.checkBody('firstName','First Name is Required').notEmpty();
    req.checkBody('lastName','Last Name is Required').notEmpty();
    req.checkBody('password','Password is Required').notEmpty();
    req.checkBody('password1','Passwords do not match').equals(req.body.password);
    
    var errors = req.validationErrors();
    if(errors){
        res.render('Sregister', {errors: errors});
    }else{
    bcrypt.genSalt(10, function(err,  salt){
        bcrypt.hash(newUser.password, salt, function(err, hash){
            if(!err){
                newUser.password = hash;
            }
            newUser.save(function(err){
                if(!err){
                    console.log("success in reg");
                    res.redirect("/student/login")
                }
            })
        })
    })
    }}
    else if(type=="teacher"){
        var newUser = new Teacher({
        username: req.body.username,
        gender: req.body.gender,
        //rollnumber: req.body.rollnumber,
        dob: req.body.dob,
        email: req.body.email,
        type: req.body.type,
        password: req.body.password,
        firstName: req.body.firstName,
        lastName: req.body.lastName
    })
    console.log(req.body.username)
    
    req.checkBody('username','UserName is Required').notEmpty();
    //req.checkBody('rollnumber','Roll Number is Required').notEmpty();
    req.checkBody('email','Email Required').notEmpty();
    req.checkBody('firstName','First Name is Required').notEmpty();
    req.checkBody('lastName','Last Name is Required').notEmpty();
    req.checkBody('email','Email Invalid').isEmail();
    req.checkBody('password','Password is Required').notEmpty();
    req.checkBody('password1','Passwords do not match').equals(req.body.password);
    
    var errors = req.validationErrors();
    if(errors){
        res.render('Sregister', {errors: errors});
    }else{
    
             bcrypt.genSalt(10, function(err,  salt){
                 bcrypt.hash(newUser.password, salt, function(err, hash){
                    if(!err){
                         newUser.password = hash;
                  }
                        newUser.save(function(err){
                     if(!err){
                         console.log("success in reg");
                         res.redirect("/teacher/login")
                }
            })
        })
    })
    }}
})

//STRATEGIES

passport.use('student', new LocalStrategy(function(username, password, done){
    var query = {username: username};
    Student.findOne(query, function(err, student){
        if(err) throw err;
        if(!student){
            return done(null, false);
        }
        bcrypt.compare(password,student.password, function(err, isMatch){
            if(err) throw err;
            if(isMatch)
                return done(null, student);
            else
                return done(null,false);
        })
    })
}))

passport.use('teacher', new LocalStrategy(function(username, password, done){
    var query = {username: username};
    console.log(query)
    Teacher.findOne(query, function(err, teacher){
        if(err) throw err;
        if(!teacher){
            console.log("no teach")
            return done(null, false);
        }
        bcrypt.compare(password,teacher.password, function(err, isMatch){
            if(err) throw err;
            if(isMatch)
                return done(null, teacher);
            else
                return done(null,false);
        })
    })
}))

//SERIALIZE AND DESERIALIZE

passport.serializeUser(function (entity, done) {
    done(null, { id: entity.id, type: entity.type });
});

passport.deserializeUser(function (obj, done) {
    switch (obj.type) {
        case 'student':
            Student.findById(obj.id)
                .then(user => {
                    if (user) {
                        done(null, user);
                    }
                    else {
                        done(new Error('user id not found:' + obj.id, null));
                    }
                });
            break;
        case 'teacher':
            Teacher.findById(obj.id)
                .then(device => {
                    if (device) {
                        done(null, device);
                    } else {
                        done(new Error('device id not found:' + obj.id, null));
                    }
                });
            break;
        default:
            done(new Error('no entity type:', obj.type), null);
            break;
    }
});

//LOGIN

app.get("/student/login", function(req, res){
    res.render("Slogin")
})

app.get("/teacher/login", function(req, res){
    res.render("Tlogin")
})

  
app.post('/student/login', 
  passport.authenticate('student', { failureRedirect: '/student/login' }), function(req, res){
      res.redirect('/student/' + req.body.username +'/profile')
  });

app.post('/teacher/login', 
  passport.authenticate('teacher', { failureRedirect: '/teacher/login' }), function(req, res){
      //console.log(req.body._id)
      res.redirect('/teacher/' + req.body.username +'/profile')
  });
  
//LOGOUT

app.get("/logout", function(req, res){
    console.log("logged out")
    req.logout();
    res.redirect("/");
})

//--------------
//ALUMINI ROUTES
//--------------

app.get("/", function(req, res){
   res.render("home"); 
});
//PROFILE DISPLAY
app.get("/student/:id/profile", function(req, res){
    var username = req.params.id;
    Student.findOne({username:username}, function(err, student){
        if(err) throw err;
        else{
                    res.render("sprofile", {student: student});
        }
    })
});

app.post("/student/:id/profile", function(req, res){
    var username = req.params.id;
    Student.findOne({username: username}, function(err, student){
        if(err) throw err;
        else{
            student.exp.push({
                projname: req.body.projname,
                fromdate: req.body.fromdate,
                todate: req.body.todate,
                teachername: req.body.teachername,
                description: req.body.descp
            });
            //console.log(req.body.teachername)
            Teacher.findOne({username: req.body.teachername}, function(err, teacher){
            if(err) throw err;
            else{
                teacher.stu.push({
                    stufirstname: student.firstName,
                    stulastname: student.lastName,
                    sturoll: student.username,
                    stuproj: req.body.projname,
                    stufromdate: req.body.fromdate,
                    stutodate: req.body.todate,
                    studescp: req.body.descp
                    
                });
                console.log(req.body.projname)
                teacher.save(function(err, teacher){
                if(err) throw err;
                else{
                        //res.render("sprofile", {student: student});
                }
            })
            }
        })
            student.save(function(err, student){
                if(err) throw err;
                else{
                        res.render("sprofile", {student: student});
                }
            })
        }

    })
})

app.get("/teacher/:id/profile", function(req, res){
    var username = req.params.id;
    //console.log(req.params.id)
    Teacher.findOne({username:username}, function(err, teacher){
        if(err) throw err;
        else{
            res.render("tprofile", {teacher: teacher});
        }
    })
});
//EDIT PROFILE
app.get("/student/:id/edit", function(req, res){
    var username = req.params.id;
    Student.findOne({username:username}, function(err, student){
        if(err) throw err;
        else{
            res.render("sedit", {student: student});
        }
    })
});

app.get("/teacher/:id/edit", function(req, res){
    var username = req.params.id;
    Teacher.findOne({username: username}, function(err, teacher){
        if(err) throw err;
        else{
            res.render("tedit", {teacher: teacher});
        }
    })
});

app.put("/student/:id/edit", function(req, res){
    var username = req.params.id;
    Student.findOneAndUpdate({username: username},req.body.student, function(err, foundStudent){
        if(err)
            res.redirect("/student/"+req.params.id+"/edit")
        else{
            res.redirect("/student/"+req.params.id+"/profile")
        }
    })
})

app.put("/teacher/:id/edit", function(req, res){
    var username = req.params.id;
    Teacher.findOneAndUpdate({username: username},req.body.teacher, function(err, foundTeacher){
        if(err)
            res.redirect("/teacher/"+req.params.id+"/edit")
        else{
            res.redirect("/teacher/"+req.params.id+"/profile")
        }
    })
})


app.listen(process.env.PORT, process.env.IP, function(){
   console.log("SERVER INITIATED"); 
});