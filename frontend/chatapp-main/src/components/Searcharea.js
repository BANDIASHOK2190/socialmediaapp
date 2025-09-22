import React from "react";
import "./searcharea.css";

const STYLES = "search-area";

export const Searcharea = ({ type, searchStyle, onChange, value }) => {
  const SearchStyle = STYLES.includes(searchStyle) ? searchStyle : STYLES;
  return (
    <div className="search-area-wrapper">
      <div
        className={`search-area ${SearchStyle}`}
        type={type}
        action="/url"
        method="GET"
      >
        <img className={"search-icon"} src="searchicon.png" alt="search-icon" />
        <input type="text" placeholder="Search by a course name" onChange={onChange} value={value}/>
      </div>
    </div>
  );
};

/* 
//DON'T FORGET TO IMPORT THE COMPONENT!
    <Searcharea></Searcharea>
*/
