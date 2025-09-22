import React, { useEffect, useState } from "react";
import "./SearchChat.css";
import { Searcharea } from "../Searcharea";
import Parse from "parse/dist/parse.min.js";

export const SearchChat = ({ loggedInUser, newChatCallback, selectChatCallback, contactInfoCallback }) => {
  const [search, setSearch] = useState("");
  const [course, setCourse] = useState(null);
  const [groupChat, setGroupChat] = useState(null);
  const [user, setUser] = useState(null);

  useEffect(() => {
    const findCourseList = async function () {
      const courseQuery = new Parse.Query("Course");
      courseQuery.includeAll();
      const chatQuery = new Parse.Query("Chat");
      chatQuery.exists("group_name");
      const userQuery = new Parse.Query("User");

      try {
        let courseList = await courseQuery.find();
        let chatList = await chatQuery.find();
        let userList = await userQuery.find();
        setGroupChat(chatList);
        setCourse(courseList);
        setUser(userList);
        return true;
      } catch (error) {
        alert(`Error!${error.message}`);
        return false;
      }
    };
    findCourseList();
  }, []);

  //codes partially from https://stackoverflow.com/questions/69360279/return-no-result-found-state-on-search-in-react
  const findUserInCourse = (data) => {
    const filterUser = data.filter((item) =>
  item.get("Guest_uni_course") !== undefined ? item.get("Guest_uni_course").toLowerCase().includes(search.toLowerCase()) : console.log()
  );
    if(!filterUser.length) return <li className="list-item" >No users found by this course name</li>
    return filterUser.map((item, index) => (item.get("User_ID").id !== loggedInUser &&
        <li key={`${index}`} className="list-item" 
        onClick={() => {
          //startNewChat(item.get("User_ID"));
          newChatCallback(item.get("User_ID")); // deliver a user object
          contactInfoCallback(item.get("User_ID"));
          setSearch("");
          }}>
          {`${item.get("User_ID").get("firstName")} 
            ${item.get("User_ID").get("lastName")}:
            ${item.get("Guest_uni_course")}`}
        </li>
      ));
  };

  const findUserbyName = (data) => {
    const filterUser = data.filter((item) =>
    `${item.get("firstName")} ${item.get("lastName")}`.toLowerCase().includes(search.toLowerCase())
  );
    if(!filterUser.length) return <li className="list-item" >No users found by this name</li>
    return filterUser.map((item, index) => (item.id !== loggedInUser &&
        <li key={`${index}`} className="list-item" 
        onClick={() => {
          newChatCallback(item); // deliver a user object
          contactInfoCallback(item);
          setSearch("");
          }}>
          {`${item.get("firstName")} 
            ${item.get("lastName")}`}
        </li>
      ));
  };

  const findCourseGroup = (data) => {
    const filterGroup = data.filter((item) =>
    item.get("group_name") !== undefined ? item.get("group_name").toLowerCase().includes(search.toLowerCase()) : console.log()
    );
    if(!filterGroup.length) return <li className="list-item" >No group found</li>
    return filterGroup
      .map((item, index) => (
        <li key={`${index}`} className="list-item" 
        onClick={() => {
          newChatCallback(item); // deliver a user object
          contactInfoCallback(item);
          setSearch("");
          }}>
          {`Group: ${item.get("group_name")}`}
        </li>
      ));
  };

  return (
    <div className="container">
      <Searcharea onChange={(e) => setSearch(e.target.value)} value={search}></Searcharea>
      {search !== "" &&
      <div className="result-container">
        <ul className="result-list">
          <p className="category">Users by course name</p>
          {course !== null && findUserInCourse(course)}
        </ul>
        <ul className="result-list">
          <p className="category">Users by name</p>
          {user !== null && findUserbyName(user)}
        </ul>
        <ul className="result-list">
        <p className="category">Groups</p>
        {groupChat !==null && findCourseGroup(groupChat)}
        </ul>
      </div>}
    </div>
  );
};
