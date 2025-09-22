import RegisterForm from "../components/RegisterForm";
import Parse from "parse/dist/parse.min.js";
import { useState } from "react";
import {useNavigate} from "react-router-dom";


export default function Registration(props) {

  const[signupsuccess, setSignupSuccess]=useState(false);
  const navigate=useNavigate();

  const registerDataToBackendFunc = async (userData, setError) => {

    const user = new Parse.User();
    user.set("username", userData.email);
    user.set("email", userData.email);
    user.set("password", userData.password);
    user.set("firstName", userData.firstName);
    user.set("lastName", userData.lastName);
    
    const chatQuery = new Parse.Query('Chat');
    chatQuery.equalTo("objectId", "A6Qh6AQVNF");
 
    try {
    await user.signUp();

    let chat = await chatQuery.first();
    let userRelation = chat.relation('user_id');
    userRelation.add(user);
    await chat.save();

    const courseQuery = new Parse.Object('Course');
    courseQuery.set("User_ID", user);
    await courseQuery.save();
  
    const skillQuery = new Parse.Object('Skills');
    skillQuery.set('User_ID', user);
    await skillQuery.save();

    navigate("/registration/popup", {state:{name:userData.firstName}});
    }
    catch(error)
    {
     alert(
      `error ! ${error}`
     );
     setSignupSuccess(false);
    }

  };

  const successStatus=signupsuccess;

  return <RegisterForm registerFunction={registerDataToBackendFunc} success={successStatus}/>;
}
