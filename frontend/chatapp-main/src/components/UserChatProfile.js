import "./UserChatProfile.css";
import Parse from "parse/dist/parse.min.js";
import React, { useState, useEffect } from "react";
import { UserAvatar } from "../components/UserAvatar";
import avartarImg from "../images/main-avatar-image.png";
import { useNavigate } from "react-router-dom";

export const UserChatProfile = ({ userId }) => {
  // State variables
  const [person, setPerson] = useState(null);
  const [school, SetSchool] = useState(null);
  const [group, setGroup] = useState(null);
  const navigate = useNavigate();

  function toUserObject(user) {
    return {
      firstName: user.get("firstName"),
      lastName: user.get("lastName"),
      userId: user.id,
      userImage: user.get("Image") ? user.get("Image")._url : avartarImg,
    };
  }

  function toGroupObject(group) {
    return {
      groupName: group.get("group_name") ? group.get("group_name") : "Group Name",
      groupImage: group.get("group_image") ? group.get("group_image")._url : avartarImg,
      id: group.id,
    };
  }

  function toSchoolObject(school){
    return {
      university: school.get("Home_university") ? school.get("Home_university") : "No home uni info yet",
      degree: school.get("Home_university_degree") ? school.get("Home_university_degree") : "No degree info yet",
      id: school.id,
    };
  }

  useEffect(() => {
    async function fetchPerson() {
      // create your Parse Query using the Person Class you've created
      const query = new Parse.Query("User"); // user name
      const chatQuery = new Parse.Query("Chat");
      const schoolQuery = new Parse.Query("Course"); // user school

      // run the query
      // use the equalTo filter to look for user with this id.
      query.equalTo("objectId", userId);
      const Person = await query.first();

      if (Person === undefined) {
        chatQuery.equalTo("objectId", userId);
        const Group = await chatQuery.first();
        const groupOject = Group !== undefined ? toGroupObject(Group) : null;
        setPerson(null);
        SetSchool(null);
        setGroup(groupOject);
      } else {
        schoolQuery.equalTo("User_ID", Person.toPointer());
        const School = await schoolQuery.first();
        const personObject = toUserObject(Person);
        const schoolObject = toSchoolObject(School);
        setGroup(null);
        setPerson(personObject);
        SetSchool(schoolObject);
      }
    }

    fetchPerson();
  }, [userId]);

  return (
    <div>
      {person !== null && person !== undefined && (
        <div className="user-info">
          <UserAvatar
            avatarSize="size52"
            statusIcon="icon--off"
            imgUrl={person.userImage}
            onClick={()=> navigate(`/profile/${person.userId}`)}
          ></UserAvatar>

          <div className="user-sort-info">
            <p className="user-name">{`${person.firstName} ${person.lastName}`}</p>
            <p>{`${school.university} ${school.degree}`}</p>
          </div>
        </div>
      )}

      {group !== null && group !== undefined && (
        <div className="user-info">
          <UserAvatar
            avatarSize="size52"
            statusIcon="icon--off"
            imgUrl={group.groupImage}
          ></UserAvatar>

          <div className="user-sort-info">
            <p className="user-name">{group.groupName}</p>
          </div>
        </div>
      )}
    </div>
  );
};

/*
export function UserChatProfile() {
  retrieveUser();

  return (
      <div className={"user-name"}>
      </div>
        <UserName name={userName}/>
        <UserSchool school="ITU, Front-End Developer" />
  );
}
*/
