import React, { useState } from "react";
import "./PopUp.css";
import {useNavigate,useLocation} from "react-router-dom";

function PopUp(props) {
  //Usestate - using "setModal" to change the state of "modal"
  const [modal, setModal] = useState(true);
  const navigateregisterpage=useNavigate();
  const location=useLocation();
  const successContent=`${location.state.name} have been successfully registered!!`;
  
  //function on the popup 
  const toggleModal = () => {
    setModal(!modal);
    navigateregisterpage("/");
  };

  return (
  <>

      {modal && (
        <div className="modal">
          <div onClick={toggleModal} className="popup--overlay"></div>
          <div className="modal-content">
            <h2>Register</h2>
            <p> {successContent}<br />
            <br/>
            Please close to go back to login<br />
            </p>
            <button className="close-modal" onClick={toggleModal}>❌</button>
          
          </div>
        </div>
      )}
  </>
  )
}
export default PopUp;