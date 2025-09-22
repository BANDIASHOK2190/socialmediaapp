import React from "react";
import "./button.css";

//Button style refers to the color of the button
//Button size refers to the width and height of the button
const STYLES = [
  "btn--default", 
  "btn--white",
  "btn--red"];
const SIZES = [
  "btn--width170--height60",
  "btn--width230--height50",
  "btn--width250--height50",
  "btn--width195--height50",
  "btn--width120--height50",
  "btn--width140--height40",
  "btn--width100--height40",
];
//It is not a wrapper. This pattern(children prop) allows you to put other children inside(i.e images) and has the potential of becoming a wrapper
export const Button = ({
  children,
  type,
  onClick,
  buttonStyle,
  buttonSize,
}) => {
  const checkButtonStyle = STYLES.includes(buttonStyle)
    ? buttonStyle
    : STYLES[0];
  const checkButtonSize = SIZES.includes(buttonSize) 
    ? buttonSize 
    : SIZES[0];
  return (
      <button
        className={`btn ${checkButtonStyle} ${checkButtonSize}`}
        onClick={onClick}
        type={type}
      >
        {children}
      </button>
  );
};

/*
<Button
  type="button"
  buttonSize="btn--width140--height40"
  buttonStyle={"btn--white"}
>
*/