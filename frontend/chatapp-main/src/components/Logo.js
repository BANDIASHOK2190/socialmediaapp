import React from "react";
import "./Logo.css";

const STYLES = "logo";
  //It is not a wrapper. This pattern(children prop) allows you to put other children inside(i.e images) and has the potential of becoming a wrapper
  export const Logo = ({
    logoStyle
  }) => {
    const LogoStyle = STYLES.includes(logoStyle)
      ? logoStyle
      : STYLES;
    return (
        <div className={`logo-wrapper ${LogoStyle}`}>

            <div className="text-logo">
                <img src="sendITlogo.png"/>
            </div>

            <div className="book-image">
                <img src="Subtractlogoandslogan.png"/>
            </div>

        </div>
    );
  };


