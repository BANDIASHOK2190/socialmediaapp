import { DefaultInputField } from "../DefaultInputField";
import "./SendMessage";
import { useEffect, useState } from "react";
import Parse from "parse/dist/parse.min.js";
import { Button } from "../Button";

function SendMessage(props) {
  //react hook to update the message state
  const [message, updateMessage] = useState("");

  function setMessagecontent(e) {
    updateMessage(e.target.value);
  }

  const chatid = props.chatId;
  const userid = props.loggedInUserId;
  let date1 = new Date();

  async function handleEnter(event) {
    if (event.key === "Enter") {
      await insertdataintoMessage();
    }
  }


  async function insertdataintoMessage() {
    if (message !== "") {
      let Message = new Parse.Object("Message");
      Message.set("content", message);
      Message.set("timestamp", date1);
      const currentuserid = new Parse.User({ id: userid });
      console.log(currentuserid);
      const currentChatId = new Parse.Query("Chat");
      currentChatId.equalTo("objectId", chatid);
      let senderNicknameObject = await currentChatId.first();

      Message.set("user", currentuserid.toPointer());
      Message.set("chat", senderNicknameObject.toPointer());

      Message = await Message.save();
      console.log(Message.id);

      senderNicknameObject.set("last_message", Message.toPointer());
      senderNicknameObject.save();
      
      updateMessage("");
    }
  }
 
  return (
    <div className="send-message-container">
      <DefaultInputField
        type="text"
        placeholder={"Type your message here"}
        onChange={setMessagecontent}
        value={message}
        onKeyDown={handleEnter}
      ></DefaultInputField>
      
      <Button
        buttonSize="btn--width100--height40"
        onClick={insertdataintoMessage}
      >
        send
      </Button>
    </div>
  );
}
export default SendMessage;
