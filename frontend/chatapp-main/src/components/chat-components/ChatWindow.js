import React from "react";
import "./chat-window.css";
import { ChatBubble } from "./ChatBubble";
import { useEffect, useRef } from "react";
import { useState } from "react";
import { ConvertResultToMessage, GetChatMessages, GetChatSubscription } from "./MessageClient";

function CreateChatRow(message, loggedInUserId) {
    const messageUserID = message.userId;
    const isReceiver =  loggedInUserId === messageUserID;
    const bubbleStyle = isReceiver ? "chat--bubble--receiver" : "chat--bubble--sender";
    const rowStyle = isReceiver ? "chat-row-receiver" : "chat-row-sender";
   
    return (
            <div className={rowStyle} key={message.messageId}>
                <ChatBubble bubbleStyle={bubbleStyle} userName={message.userName} seen={message.seen} time={message.date}>{message.content}</ChatBubble>
            </div>
    );
}

function insertIfNotExists(message, messages) {
    for(let i = 0; i < messages.length; i++) {
        if (message.messageId === messages[i].messageId) {
            return messages;
        }
    }
    const newMessages = [...messages, message]; 
    
    return newMessages;

}

export const ChatWindow = ({
  chatId,
  loggedInUserId
}) => {
        const divRef = useRef(null);
        const [messages, setMessages] = useState([]);
        const [ , setNewMessageSubscription] = useState(undefined);

        //show old and new messages 
        useEffect( () => {
            async function SetUpChat() {
                //console.log('SetUpChat called!');
                // You can await here
                    const oldMessages = await GetChatMessages(chatId, 1000);
                    setMessages(oldMessages); 
                    
                    const subscription = GetChatSubscription(chatId);
                    //everytime a new message is created in b4app, subcription.on() will be called with the message parameter
                    subscription.on('create', message => { //step 3.1 create event code taken from: https://www.back4app.com/docs/platform/parse-server-live-query-example
                        const newMessage = ConvertResultToMessage(message);
                        //setMessages(previousMessages => [...previousMessages, newMessage]); //the variable messages is an array and we add the element message to it. But we are not able to display those changes. setMessages helps us to see these changes
                        setMessages(previousMessages => insertIfNotExists(newMessage, previousMessages))

                        console.log(newMessage);
                    });

                    setNewMessageSubscription(subscription);
            }

            SetUpChat();
                
        },[chatId]);

        useEffect(() => divRef.current.scrollIntoView({ behavior: 'instant' }), [messages]);   //code and use of useEffect and useRef hook is inspired and taken by stackoverflow https://stackoverflow.com/questions/37620694/how-to-scroll-to-bottom-in-react and https://www.folkstalk.com/2022/09/scrollbar-automatically-scroll-down-as-new-divs-are-added-reactjs-with-code-examples-2.html


    return (
         <div className={"layout"}>
        <div className="chat--bubble--box">
            {
                messages.map(message => CreateChatRow(message, loggedInUserId)) //takes array named messages
            }
            <div ref={divRef}/> 
        </div>
     </div>
  );
};
