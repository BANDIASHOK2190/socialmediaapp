import React from 'react'
import './UserAvatar.css';

const SIZES = [
    "size32",
    "size48",
    "size52", 
    "size250"
];

const ICONSTATUS = [
    "icon--for--size32", 
    "icon--for--size48", 
    "icon--for--size52", 
    "icon--for--size250", 
    "icon--off"
];

export const UserAvatar = ({ 
    avatarSize,
    statusIcon,
    onClick,
    imgUrl
}) => {

    const checkStatusIcon = ICONSTATUS.includes(statusIcon) ? statusIcon : ICONSTATUS[1];
    const checkAvatarSize = SIZES.includes(avatarSize) ? avatarSize : SIZES[1];
    
    return (
         <div 
            className={`avatar ${checkAvatarSize}`} 
            onClick={onClick}>
                <img src={`${imgUrl}`} className={`${checkAvatarSize}`}/>
                <p className={`icon ${checkStatusIcon}`}></p>
         </div>  
    )
}

/*
//COMPONENT IN JSX! DON'T FORGET TO IMPORT THE COMPONENT!

import {UserAvatar} from '../components/UserAvatar'
import avartarImg from '../images/main-avatar-image.png'
    <div>
        <UserAvatar onClick={() => {console.log("You clicked on me!")}}
        avatarSize="size48" statusIcon="icon--for--size48" 
        imgUrl={avartarImg}> 
        </UserAvatar>
    </div>
*/