import React from "react";
import "./emaillinkinputfield.css";

const STYLES = "email--link--default";

export const EmailLinkInputField = ({
  type,
  onClick,
  emailLinkStyle,
  labelText,
  placeholder,
}) => {
  const checkemailLinkStyle = STYLES.includes(emailLinkStyle)
    ? emailLinkStyle
    : STYLES;

  return (
    <div>
      <div
        className={`email-input-field ${checkemailLinkStyle}`}
        onClick={onClick}
        type={type}
      >
        <div className="email-l-div">
          <div className="email-label-div">
            <label>{labelText}</label>
            <div className="input">
              <input
                className="email-link-input"
                type="text"
                placeholder={placeholder}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

/* 
// COMPONENT IN JSX! DON'T FORGET TO IMPORT THE COMPONENT!
<EmailLinkInputField labelText={'egg'} placeholder={'egg'}></EmailLinkInputField>

*/
