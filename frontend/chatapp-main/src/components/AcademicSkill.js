import "./AcademicSkill.css";
import React, { useState }  from "react";
import { Icon } from "@iconify/react";

export const AcademicSkill = ({ skillName, skillRating }) => {
  return (
    <div className='skill'>
      <p className='skill--title'>{skillName}</p>
      {starDisplay(skillRating)}
    </div>
  );
};

function starDisplay(skillRating){
    let content = [];

    for(let i = 0; i < 5; i++){
        if(Number(skillRating) > i){
            content.push(<Icon key={i} icon="ic:round-star" color="#50a161" inline={true}/>);
        } else {
            content.push(<Icon key={i} icon="ic:round-star-border" color="#50a161" inline={true} />);
        }
    }

    return <span>{content}</span>;
}


/*
//COMPONENT IN JSX! DON'T FORGET TO IMPORT THE COMPONENT!
import {AcademicSkill} from '../components/AcademicSkill'
    <div>
        <AcademicSkill skillName="Python" skillRating="3"> 
        </AcademicSkill>
    </div>
*/
