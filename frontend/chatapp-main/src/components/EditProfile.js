import "./EditProfile.css";
import React, { useState, useEffect } from "react";
import Parse from "parse/dist/parse.min.js";
import Layout from "./Layout";
import { DefaultInputField } from "./DefaultInputField";
import { LargeInputField } from "./LargeInputField";
import { Button } from "./Button";
import { useNavigate } from "react-router-dom";
import { DropDown } from "./DropDown";

function EditProfile() {
  const [currentUserId, setCurrentUserId] = useState(null);
  const [currentCourseId, setCurrentCourseId] = useState(null);
  const [currentSkillId, setCurrentSkillId] = useState(null);
  const [userInfo, setUserInfo] = useState({
    firstName: "",
    lastName: "",
    email: "",
    bio: "",
    image: "",
  });
  const [image, setImage] = useState(null);
  const [studyinfo, setStudyInfo] = useState({
    HomeUniversity: "",
    StudyProgram: "",
    ITUcourse: "",
  });
  const [Error, setError] = useState({
    skillError: "",
    ratingError: "",
  });
  const [selectSkill, setSelectSkill] = useState(null);
  const [openSkill, setOpenSkill] = useState(false);
  const [selectRating, setSelectRating] = useState(null);
  const [openRating, setOpenRating] = useState(false);
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
  const ratings = ["1", "2", "3", "4", "5"];
  const skillBackend = [
    "Front_end_development",
    "Backend_development",
    "python",
    "Design",
    "Business_Analytics",
    "CloudArchitecture",
    "ProductManagement",
    "ScrumMaster",
    "InformationSecurity",
    "Research",
  ];

  const navigate = useNavigate();

  useEffect(() => {
    const checkCurrentUser = async () => {
      try {
        const user = await Parse.User.current();
        if (user === null || user === undefined) {
          alert("Please log in first!");
          navigate("/");
        } else {
          if (currentUserId === null) {
            setCurrentUserId(user.id);

            const courseQuery = new Parse.Query("Course");
            courseQuery.equalTo("User_ID", user.toPointer());
            const course = await courseQuery.first();
            setCurrentCourseId(course.id);

            const skillQuery = new Parse.Query("Skills");
            skillQuery.equalTo("User_ID", user.toPointer());
            const skill = await skillQuery.first();
            setCurrentSkillId(skill.id);
          }
        }
        return true;
      } catch (_error) {}
      return false;
    };
    checkCurrentUser();
  }, []);

  function handleFirstName(e) {
    setUserInfo({
      ...userInfo,
      firstName: e.target.value,
    });
  }

  function handleLastName(e) {
    setUserInfo({
      ...userInfo,
      lastName: e.target.value,
    });
  }

  function handleImage(e) {
    setImage(e.target.files[0]);
  }

  function handleHomeUni(e) {
    setStudyInfo({
      ...studyinfo,
      HomeUniversity: e.target.value,
    });
  }

  function handleMajor(e) {
    setStudyInfo({
      ...studyinfo,
      StudyProgram: e.target.value,
    });
  }

  function handleCourse(e) {
    setStudyInfo({
      ...studyinfo,
      ITUcourse: e.target.value,
    });
  }

  function handleBio(e) {
    setUserInfo({
      ...userInfo,
      bio: e.target.value,
    });
  }

  async function saveChanges(e) {
    let hasError = false;

    if (selectRating !== null || selectSkill !== null) {
      if (selectRating !== null && selectSkill !== null) {
        const updateSkill = new Parse.Object("Skills");
        updateSkill.set("objectId", currentSkillId);
        selectSkill !== null &&
          skillSet.map(
            (item, index) =>
              item === selectSkill &&
              selectRating !== null &&
              updateSkill.set(skillBackend[index], selectRating)
          );
          try {
          await updateSkill.save();
          } catch (error) {
            alert(`Error!${error.message}`);
            return false;
          }
      } else {
        selectRating === null
          ? setError({ ...Error, ratingError: "Please rate this skill" })
          : setError({
              ...Error,
              skillError: "Please select a skill for this rating",
            });
        hasError = true;
        e.preventDefault();
      }
    }

    if (!hasError) {
      if (
        userInfo.firstName.trim() !== "" ||
        userInfo.lastName.trim() !== "" ||
        userInfo.bio.trim() !== "" ||
        image !== null
      ) {
        const updateUser = new Parse.User();
        updateUser.set("objectId", currentUserId);
        userInfo.firstName.trim() !== "" &&
          updateUser.set("firstName", userInfo.firstName);
        userInfo.lastName.trim() !== "" &&
          updateUser.set("lastName", userInfo.lastName);
        userInfo.bio.trim() !== "" && updateUser.set("bio", userInfo.bio);
        if (image !== null){
          const userImage = new Parse.File(image.name, image);
          await userImage.save();
          updateUser.set("Image", userImage);
        }
        try {
          await updateUser.save();
        } catch (error) {
          alert(`Error!${error.message}`);
          return false;
        }
      }

      if (
        studyinfo.HomeUniversity.trim() !== "" ||
        studyinfo.StudyProgram.trim() !== "" ||
        studyinfo.ITUcourse.trim() !== ""
      ) {
        const updateCourse = new Parse.Object("Course");
        updateCourse.set("objectId", currentCourseId);
        studyinfo.HomeUniversity.trim() !== "" &&
          updateCourse.set("Home_university", studyinfo.HomeUniversity);
        studyinfo.StudyProgram.trim() !== "" &&
          updateCourse.set("Home_university_degree", studyinfo.StudyProgram);
        studyinfo.ITUcourse.trim() !== "" &&
          updateCourse.set("Guest_uni_course", studyinfo.ITUcourse);
          try {
            await updateCourse.save();
          } catch (error) {
            alert(`Error!${error.message}`);
            return false;
          }
      }
    }

    navigate("/profile");
  }

  return (
    <div className="Edit-profile-background">
      <div>
        <h2 className="Page-title">Edit Profile</h2>
      </div>
      <form className="edit-form">
        <DefaultInputField
          labelText={"First Name"}
          placeholder={"Modify your first name"}
          onChange={handleFirstName}
        ></DefaultInputField>

        <DefaultInputField
          labelText={"Last Name"}
          placeholder={"Modify your last name"}
          onChange={handleLastName}
        ></DefaultInputField>
        
        <DefaultInputField
          type={"file"}
          labelText={"Profile Picture"}
          placeholder={"Upload your image"}
          onChange={handleImage}
        ></DefaultInputField>

        <DefaultInputField
          labelText={"Home University"}
          placeholder={"Your home university name"}
          onChange={handleHomeUni}
        ></DefaultInputField>

        <DefaultInputField
          labelText={"Study program"}
          placeholder={"Your Study program (e.g. Software Design)"}
          onChange={handleMajor}
        ></DefaultInputField>

        <DefaultInputField
          labelText={"Course at ITU"}
          placeholder={"Name of the course you're taking at ITU"}
          onChange={handleCourse}
        ></DefaultInputField>

        <div className="skill-rating">
          <DropDown
            labelText={"Academic skill (save one at a time)"}
            placeholder={"Select a skill from the dropdown"}
            options={skillSet}
            onChange={(item) => setSelectSkill(item)}
            open={openSkill}
            setOpen={setOpenSkill}
            error={Error.skillError}
          ></DropDown>

          <DropDown
            labelText={"Skill Rating"}
            placeholder={"Rate your skill (1-5)"}
            options={ratings}
            onChange={(item) => setSelectRating(item)}
            open={openRating}
            setOpen={setOpenRating}
            error={Error.ratingError}
          ></DropDown>
        </div>

        <LargeInputField
          type={"text"}
          labelText={"Add your bio"}
          placeholder={"Describe yourself in few words"}
          onChange={handleBio}
        ></LargeInputField>

        <div className="pagecontrols">
        <Button
          type="button"
          buttonSize="btn--width140--height40"
          onClick={() => {
            saveChanges();
          }}
        >
          save
        </Button>
        <Button
          type="button"
          buttonSize="btn--width140--height40"
          buttonStyle="btn--white"
          onClick={() => {
            navigate("/profile");
          }}
        >
          Cancel
        </Button>
        </div>
      </form>
    </div>
  );
}
export default EditProfile;
