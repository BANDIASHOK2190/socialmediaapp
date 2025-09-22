import './App.css';
import Registration from './Pages/Registration';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import LoginPage from './Pages/LoginPage';
import ProfilePage from './Pages/ProfilePage';
import Parse from "parse/dist/parse.min.js";
import { ChatPageLayout } from './Pages/ChatPageLayout';
import PopUp from "./components/PopUp";
import  { createContext } from "react";
import EditProfile from './components/EditProfile';
import SendMessage from './components/SendMessage/SendMessage';

const Parse_application_id='gvIXi223QYLFMqdL8dMAd8yRUptGZkDjKkCOf7bk';
const Parse_host_URL='https://parseapi.back4app.com';
const Parse_Javascript_key='SRsW7tBVQHEDAlOlS2xBqwy6vaFRndgcBUlF5G4Z';

Parse.initialize(Parse_application_id, Parse_Javascript_key);
Parse.serverURL = Parse_host_URL;

// react context usage
export const UserContext = createContext();

function App() {
  return (
    <BrowserRouter>
    <Routes>
      <Route exact path="/" element={<LoginPage />} />
      <Route exact path="/registration" element={<Registration />} />
      <Route exact path="/profile" element={<ProfilePage />} />
      <Route exact path="/chat" element={<ChatPageLayout />} />
      <Route exact path="/registration/popup" element={<PopUp />} />
      <Route exact path="/profile/edit" element={<EditProfile/>} />
      <Route exact path="/sendmessage" element={<SendMessage/>} />
      <Route exact path="/profile/:userId" element={<ProfilePage />} />
    </Routes>
  </BrowserRouter>
  );
}
export default App;
