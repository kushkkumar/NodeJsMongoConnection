var mongodb=require('mongodb');
var ObjectID=mongodb.ObjectID;
var crypto=require('crypto');
var express=require('express');
var bodyParser=require('body-parser');

//Password ultils
//create function to random salt

var genRandomString=function(length){
    return crypto.randomBytes(Math.ceil(length/2))
    .toString('hex')
    .slice(0,length);
};
var sha512=function(Password,salt){
    var hash=crypto.createHmac('sha512',salt);
    hash.update(Password);
    var value=hash.digest('hex');
    return{
        salt:salt,
        PasswordHash:value
    };
};
function saltHashPassword(userPassword){
    var salt=genRandomString(16);//create 16 random charecter
    var passwordData=sha512(userPassword,salt);
    return passwordData;
}
function checkHashPassword(userPassword,salt){
    var passwordData=sha512(userPassword,salt);
    return passwordData;
}

//Creating Express service

var app=express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:true}));


//create MongoDB client
var MongoClient=mongodb.MongoClient;

//connection url

var url='mongodb://localhost:27017'     

// MongoClient.connect(url,{useNewUrlParser:true},function(err,client){   older version so use useUnifiedTopology

MongoClient.connect(url,{useUnifiedTopology:true},function(err,client){
    if(err){
        console.log("Unable to connect to the mongoDB server.ERROR!!!",err);

    }
    else{

        //Register
        app.post('/register',(Request,Response,next)=>{
            var post_data=Request.body;
            var plaint_password=post_data.password;  //this is the password obtained from the user
            var hash_data=saltHashPassword(plaint_password); //this is useed to encrypt the password entered by the user

            var password=hash_data.PasswordHash;  //save password hash
            var salt=hash_data.salt;

            var name=post_data.name;
            var email=post_data.email;

            var insertJSON={
                'email':email,
                'password':password,
                'salt':salt,
                'name':name
            };

            
            var db=client.db('TestLogin');
            
            //check the email exists
            
            db.collection('user')
            .find({'email':email}).count(function(err,number){
                if(number!=0){
                    Response.json('Email already exists');
                    console.log("Email already exists");
                    
                }
                else{
                    //insert data

                    db.collection('user')
                    .insertOne(insertJSON,function(error,res){
                       
                        Response.json('Registration successfull');
                        console.log("Registration successfull");

                    })

                }
            })
        });



        //Login
        app.post('/login',(Request,Response,next)=>{
            var post_data=Request.body;
           
            var email=post_data.email;
            var userPassword=post_data.password;


            
            var db=client.db('TestLogin');
            
            //check the email exists
            
            db.collection('user').find({'email':email}).count(function(err,number){
                if(number==0){
                    Response.json('Email not exists');
                    console.log("Email not exists");
                    
                }
                else{
                    //insert data

                    db.collection('user')
                    .findOne({'email':email},function(error,user){
                        var salt=user.salt;
                        var hashed_password=checkHashPassword(userPassword,salt).PasswordHash;  //hash password with salt
                        var encryptedPassword=user.password; //get password from user
                        if(hashed_password==encryptedPassword){
                            Response.json("login successfull");
                            console.log("Login successfull")
                        }
                        else{
                            Response.json("login Failed,wrong password");
                            console.log("Login Failed,wrong password")

                        }



                    })

                }
            })
        });


        //start web server
        app.listen(4000,()=>{
            console.log("Connected to mongoDB server,Webserver running in port number 4000")
        })
    }
})