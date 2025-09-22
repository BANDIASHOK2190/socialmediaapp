
import { createContext } from "react";


function usernameContext(props)
{
    const userdataContext= createContext(null);
    const userdataProvider= userdataContext.Provider;
    
    return(  
      userdataProvider
    );
}
export default usernameContext;