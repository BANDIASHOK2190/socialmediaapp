import React, { useState, useEffect } from "react";
import { ChatWindow } from "../components/chat-components/ChatWindow";
import { ChatInbox } from "../components/ChatInbox";
import Parse from "parse/dist/parse.min.js";
import "./ChatPageLayout.css";
import { UserChatProfile } from "../components/UserChatProfile";
import { SearchChat } from "../components/chat-components/SearchChat";
import SendMessage from "../components/SendMessage/SendMessage";
import { useNavigate } from "react-router-dom";

export const ChatPageLayout = () => {
  const [currentUser, setCurrentUser] = useState(null);
  const [currentChat, setCurrentChat] = useState(null);
  const [contactInfo, setContactInfo] = useState(null);
  const [newChatWith, setNewChatWith] = useState(null);
  const navigate = useNavigate();

  //codes partially from https://github.com/templates-back4app/react-js-slack-clone/blob/main/src/Home.js
  useEffect(() => {
    const checkCurrentUser = async () => {
      try {
        const user = await Parse.User.current();
        if (user === null || user === undefined) {
          alert("Please log in first!");
          navigate("/");
        } else {
          if (currentUser === null) {
            setCurrentUser(user.id);
          }
        }
        return true;
      } catch (error) {}
      return false;
    };
    checkCurrentUser();
  }, []);

  const doSelectChat = (chat) => {
    setCurrentChat(null);
    setCurrentChat(chat);
  };

  const dofindContact = (contact) => {
    setContactInfo(null);
    setContactInfo(contact); //another user's id
  };

  const startNewChatWith = (contact) => {
    setNewChatWith(null);
    setNewChatWith(contact);
  };

  return (
    <div className="main--container">
      <div className="left-container">
        <div className="user-card">
          <UserChatProfile userId={currentUser} />
        </div>
        <SearchChat
          className="search-area-wrapper"
          loggedInUser={currentUser}
          newChatCallback={startNewChatWith}
          selectChatCallback={doSelectChat}
          contactInfoCallback={dofindContact}
        />
        <div className="inbox">
          <ChatInbox
            loggedInUserId={currentUser}
            selectChatCallback={doSelectChat}
            contactInfoCallback={dofindContact}
            newChatwith={newChatWith}
          />
        </div>
      </div>

      <div className="right--container">
        <div className="sender-card">
          {contactInfo !== null && <UserChatProfile userId={contactInfo} />}
        </div>
        {currentChat !== null && (
          //console.log(currentChat.id),
          <ChatWindow chatId={currentChat.id} loggedInUserId={currentUser} />
        )}
        <div style={{fontSize: 40, marginLeft:30, color: "grey"}}>
          {currentChat === null ? "Choose a chat to start the conversation" : ""} </div>
        <div className="text-input"></div>
        {currentChat !== null && (
          <SendMessage chatId={currentChat.id} loggedInUserId={currentUser} />
        )}
      </div>
    </div>
  );
};
