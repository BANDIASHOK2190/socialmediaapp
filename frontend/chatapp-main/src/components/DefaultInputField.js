import React from "react";
import "./defaultinputfield.css";

const STYLES = "default--input";
//required doesn't let you to submit an empty input field
export const DefaultInputField = ({
  type,
  onChange,
  onKeyDown,
  inputFieldStyle,
  labelText,
  placeholder,
  error = "",
  required = false,
  value,
  readonly = false
}) => {
  const checkInputFieldStyle = STYLES.includes(inputFieldStyle)
    ? inputFieldStyle
    : STYLES;

  //if error text is not empty, then return this component
  const ErrorComponent =
    error !== "" ? (
      <div className="error-message">
        <p>{error}</p>
      </div>
    ) : null;
  return (
    <div className={`inputfield ${checkInputFieldStyle}`} type={type}>
      <div className="label-div">
        <label>{labelText}</label>
      </div>

      <div className="div-input">
        <input
          className="input-input"
          type={type}
          placeholder={placeholder}
          required={required}
          onChange={onChange}
          value={value}
          readOnly={readonly}
          onKeyDown={onKeyDown}
        />
      </div>
      {ErrorComponent}
    </div>
  );
};
/* 
// COMPONENT IN JSX! DON'T FORGET TO IMPORT THE COMPONENT!
<DefaultInputField inputFieldStyle={"default--input"} labelText={'egg'} placeholder={'egg'}></DefaultInputField>
*/
