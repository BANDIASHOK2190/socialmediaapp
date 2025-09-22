import React from 'react'
import './ClipArt.css';


export const ClipArt = ({ 
   imgUrl,
   width,
   height
}) => {

    const style = {
        width: width,
        height: height
    };

    return (
         <div 
            className={"clipart"} 
                imgUrl={imgUrl}>
                <img style={style} src={`${imgUrl}`}/>
         </div>  
    )
}