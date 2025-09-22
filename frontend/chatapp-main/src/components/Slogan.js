import React from "react";
import "./Slogan.css";

const STYLES = "slogan";
  //It is not a wrapper. This pattern(children prop) allows you to put other children inside(i.e images) and has the potential of becoming a wrapper
  export const Slogan = ({
    sloganStyle
  }) => {
    const SloganStyle = STYLES.includes(sloganStyle)
      ? sloganStyle
      : STYLES;
    return (
        <div className={`slogan-wrapper ${SloganStyle}`}>
            <div className="text-slogan">
                <img src="slogan.png"/>
            </div>
        </div>
    );
  };

