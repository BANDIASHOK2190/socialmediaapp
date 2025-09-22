import "./DropDown.css";
import React, { useEffect, useState } from "react";
import { DefaultInputField } from "./DefaultInputField";

//codes partially from https://www.youtube.com/watch?v=jaMgXmrk29M&ab_channel=ReactwithMasoud
export const DropDown = ({
  options,
  placeholder,
  onChange,
  open,
  setOpen,
  labelText,
  error,
}) => {
  const [input, setInput] = useState("");

  const handleItemSelect = (option) => {
    onChange !== undefined && onChange(option);
    onChange !== undefined && setInput(option);
    setOpen(false);
  };

  const handleInputClick = () => {
    setOpen((prevValue) => !prevValue);
  }

  function handleInput(e) {
    setInput(e.target.value);
  }

  return (
    <div className="container">
        <div className="input-container" onClick={handleInputClick}>
        <DefaultInputField
        labelText={labelText}
        placeholder={placeholder}
        value={input}
        onChange={handleInput}
        error={error}
        readonly={true}
      ></DefaultInputField>
      <div className="arrow-container">
        <i className="arrow" />
      </div>
      {input !== "" ? (
      <div className="input-clear" onClick={()=>{setInput(""); onChange(null)}}>x</div>
      ) : null}
        </div>   
      <div className={`dropdown ${open ? "visible" : ""}`}>
        {options.map((item, index) => {
          return (
            <div
              className="options"
              key={index}
              onClick={() => handleItemSelect(item, index)}
            >
              {item}
            </div>
          );
        })}
      </div>
    </div>
  );
};
