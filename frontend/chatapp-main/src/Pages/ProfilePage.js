import "./ProfilePage.css";
import React from "react";
import { Button } from "../components/Button";
import { UserAvatar } from "../components/UserAvatar";
import avartarImg from "../images/main-avatar-image.png";
import { AcademicSkill } from "../components/AcademicSkill";
import { useContext, createContext, useState, useEffect } from "react";
import usernameContext from "../components/UsernameContext";
import { useLocation, useNavigate, useParams } from "react-router-dom";
//import Parse, { User } from "parse";
import Parse from "parse/dist/parse.min.js";

// https://blog.back4app.com/building-a-real-time-react-application-with-parse/

export default function ProfilePage() {
  const userId = useParams().userId;
  const [isCurrentUser, setIsCurrentUser] = useState(false);
  const skillSet = [
    "Front-end Development",
    "Back-end Development",
    "Python",
    "Design",
    "Business Analytics",
    "Cloud Architecture",
    "Product Management",
    "Scrum Master",
    "Information Security",
    "Research",
  ];
  const [skill, setSkill] = useState(null);
  const navigate = useNavigate();
  const [studentData, fetchData] = useState({
    fname: "",
    lastname: "",
    email: "",
    bio: "",
    age: "",
    image: "",
  });
  const [studyinfo, fetchStudyInfo] = useState({
    HomeUniversity: "",
    StudyProgram: "",
    ITUcourse: "",
  });
  //const [skillData, fetchSkillData]=useState({Front_end_development:"",Business_analytics:"",CloudArchitecture:"",InformationSecurity:"",Backend_development:"",ProductManagement:"",Research:"",python:"",ScrumMaster:"",Design:"",})

  // const location=useLocation();
  // const useriddata2=location.state.data.currentUser2;
  // console.log(useriddata2);

  useEffect(() => {
    async function fetchuserdata() {
      const currentuser = await Parse.User.current();
      if (currentuser === null || currentuser === undefined) {
        alert("Please log in first!");
        navigate("/");
      } else {
        // Creating the Parse query
        const query = new Parse.Query("User");
        const courseQuery = new Parse.Query("Course");
        const skillQuery = new Parse.Query("Skills");

        try {
          //const studentid=await query.get(currentuser.id);
          let student;
          if (userId === currentuser.id || userId === undefined) {
            setIsCurrentUser(true);
            student = await query.get(currentuser.id);
          } else {
            student = await query.get(userId);
          }

          // Fetching data from User class
          const studentFirstname = student.get("firstName");
          const studentLastname = student.get("lastName");
          const studentEmail = student.get("email");
          const studentBiodata = student.get("bio");
          const studentAge = student.get("Age");
          let studentImage = "";
          if (student.get("Image")) {
            studentImage = student.get("Image")._url;
          } else {
            studentImage = avartarImg;
          }
          fetchData({
            fname: studentFirstname,
            lastname: studentLastname,
            email: studentEmail,
            bio: studentBiodata,
            age: studentAge,
            image: studentImage,
          });

          // Fetching data from Course class
          courseQuery.equalTo("User_ID", student.toPointer());
          const course = await courseQuery.first();
          const studentHomeUniversity = course.get("Home_university");
          const studentStudyProgram = course.get("Home_university_degree");
          const studentGuestUniCourse = course.get("Guest_uni_course");
          fetchStudyInfo({
            HomeUniversity: studentHomeUniversity,
            StudyProgram: studentStudyProgram,
            ITUcourse: studentGuestUniCourse,
          });

          // Fetching data from Skills class
          skillQuery.equalTo("User_ID", student.toPointer());
          const userSkill = await skillQuery.first();
          userSkill &&
            setSkill([
              userSkill.get("Front_end_development")
                ? userSkill.get("Front_end_development")
                : "0",
              userSkill.get("Backend_development")
                ? userSkill.get("Backend_development")
                : "0",
              userSkill.get("python") ? userSkill.get("python") : "0",
              userSkill.get("Design") ? userSkill.get("Design") : "0",
              userSkill.get("Business_Analytics")
                ? userSkill.get("Business_Analytics")
                : "0",
              userSkill.get("CloudArchitecture")
                ? userSkill.get("CloudArchitecture")
                : "0",
              userSkill.get("ProductManagement")
                ? userSkill.get("ProductManagement")
                : "0",
              userSkill.get("ScrumMaster") ? userSkill.get("ScrumMaster") : "0",
              userSkill.get("InformationSecurity")
                ? userSkill.get("InformationSecurity")
                : "0",
              userSkill.get("Research") ? userSkill.get("Research") : "0",
            ]);
        } catch (error) {
          alert(
            `Failed to retrieve the object, with error code: ${error.message}`
          );
        }
      }
    }
    fetchuserdata();
  }, []);

  function displaySkillHint() {
    if (skill !== null) {
      let totalRating = 0;
      skill.map((data) => {
        totalRating += Number(data);
      });

      if (totalRating === 0) {
        return <i>Add by clicking Edit Profile</i>;
      }
    }
  }

  //codes partially from https://www.back4app.com/docs/react/working-with-users/react-login
  async function userLogOut() {
    try {
      await Parse.User.logOut();
      const currentUser = await Parse.User.current();
      if (currentUser === null) {
        navigate("/");
      }
      return true;
    } catch (error) {
      alert(`Error! ${error.message}`);
      return false;
    }
  }

  return (
    <div className="profile--main--container">
      <div className="profile--leftcontainer">
        <div className="profile--leftcontainer--userinformation">
          <UserAvatar
            onClick={() => {
              console.log("You clicked on me!");
            }}
            avatarSize="size250"
            statusIcon="icon--for--size250"
            imgUrl={studentData.image}
          ></UserAvatar>
          <p>
            <b>
              {studentData.fname} {studentData.lastname}
            </b>
          </p>
          <p>
            <b>{studyinfo.ITUcourse}</b>
          </p>
          <p>
            {studentData.bio === undefined ? (
              <i>Add your profile picture and bio by clicking Edit Profile</i>
            ) : (
              studentData.bio
            )}
          </p>

          <div className="profile--leftcontainer--pagecontrols">
            <Button
              onClick={() => {
                navigate("/chat");
              }}
              type="button"
              buttonSize="btn--width250--height50"
            >
              To Chatroom
            </Button>

            {isCurrentUser && (
              <Button
                onClick={() => {
                  navigate("/profile/edit");
                }}
                type="button"
                buttonStyle="btn--white"
                buttonSize="btn--width250--height50"
              >
                Edit Profile
              </Button>
            )}

            {isCurrentUser && (
              <Button
                onClick={userLogOut}
                type="button"
                buttonSize="btn--width250--height50"
                buttonStyle="btn--red"
              >
                Logout
              </Button>
            )}
          </div>
        </div>
      </div>
      <div className="profile--rightcontainer">
        <div className="profile--rightcontainer--studyinformation">
          <h1>Study Information 🎓</h1>
          <p>
            Home University:{" "}
            {studyinfo.HomeUniversity === undefined ? (
              <i>Add by clicking Edit Profile</i>
            ) : (
              studyinfo.HomeUniversity
            )}
          </p>
          <p>
            Study Program:{" "}
            {studyinfo.StudyProgram === undefined ? (
              <i>Add by clicking Edit Profile</i>
            ) : (
              studyinfo.StudyProgram
            )}
          </p>
          <p>
            Course at ITU:{" "}
            {studyinfo.ITUcourse === undefined ? (
              <i>Add by clicking Edit Profile</i>
            ) : (
              studyinfo.ITUcourse
            )}
          </p>
        </div>

        <div className="profile--rightcontainer--skills">
          <h1>Skills 🧩</h1>
          <div className="skill--section">
            {skill !== null && displaySkillHint()}
            {skill !== null &&
              skill.map((data, index) => {
                if (data !== "0") {
                  return (
                    <AcademicSkill
                      key={`${index}`}
                      skillName={skillSet[index]}
                      skillRating={data}
                    ></AcademicSkill>
                  );
                }
              })}
          </div>
        </div>
      </div>
    </div>
  );
}
