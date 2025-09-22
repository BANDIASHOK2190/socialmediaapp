import React from "react";
import "./largeinputfield.css";

const STYLES = "large--input--field--area";

export const LargeInputField = ({
  type,
  onClick,
  largeStyle,
  labelText,
  placeholder,
  onChange,
}) => {
  const checkLargeStyle = STYLES.includes(largeStyle) ? largeStyle : STYLES;

  return (
    <div
      className={`large-input-field ${checkLargeStyle}`}
      onClick={onClick}
      type={type}
    >
      <div className="large-label-div">
        <label for="...">{labelText}</label>
      </div>

      <div className="large-input">
        <textarea
          className="large-input-fields-textarea"
          name="inputfield"
          rows="8"
          cols="50"
          placeholder={placeholder}
          onChange={onChange}
        ></textarea>
      </div>
    </div>
  );
};

/*
//COMPOINENT IN JSX! DON'T FORGET TO IMPORT THE COMPONENT.
<LargeInputField labelText={'egg'} placeholder={'egg'}></LargeInputField>
*/
