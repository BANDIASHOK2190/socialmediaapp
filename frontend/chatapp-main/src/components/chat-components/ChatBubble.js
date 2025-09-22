import React from "react";
import "./chat-bubble.css";

//use one of these array elements when getting the component
const STYLES = ["chat--bubble--receiver", "chat--bubble--sender"];
//children prop = bubble text string
export const ChatBubble = ({type, 
                            bubbleStyle,
                            userName, 
                            children, 
                            seen, 
                            time }) => {
  const BubbleStyle = STYLES.includes(bubbleStyle) ? bubbleStyle : STYLES[0];
  const seenText = seen ? "Seen" : ""; //if true return "Seen", else return an empty string ""

  return (
      <div className={`bubble ${BubbleStyle}`} type={type}>
      <div className="user-name-text">{userName}</div>
        {children}
        <div className="footer">
          <div className="time-seen-container">
            <div className="time">{getTimeText(time)}</div>
            <div className="seen">{seenText}</div>
          </div>
        </div>
      </div>
  );
};
//to get the exact time of a message we need to get a new Date (prop: time={new Date()})
// this function gets the hours and the minutes, turns them into strings
//and adds 0 wherever is missing because the initial form of the time is something like this: 8:9 instead of 08:09
//Then we use a ternary to add either the AM string or the PM
export function getTimeText(time) {
  const hours = time.getHours();
  const displayHours = hours === 12 ? 12 : hours % 12; //if time is 12 return 12, else return the remainder of hours / 12
  const displayHoursPadded = displayHours.toString().padStart(2, "0"); //3 -> 03 Reference:https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/padStart
  const displayMinutesPadded = time.getMinutes().toString().padStart(2, "0");
  const amOrPm = hours > 12 ? "PM" : "AM"; //amOrPm = AM or PM
  const timeText = `${displayHoursPadded}:${displayMinutesPadded} ${amOrPm}`;

  return timeText;
}

//Don't forget to import this component
//<ChatBubble bubbleStyle="chat--bubble--sender" seen={true} time={new Date()}>gggg</ChatBubble>
