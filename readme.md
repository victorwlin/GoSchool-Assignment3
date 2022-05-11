Live: https://guarded-wildwood-57389.herokuapp.com/

#### General Description

For this assignment, I converted the prototype submitted for Go Advanced (Assignment 2) to a client-server setup. There are four main menus that the user can interact with.

1.  **Login**  
    The user begins on the login screen, where he/she can choose to either login with username and password or sign up. For purposes of testing, the application comes with two existing users, "Victor" and "Tokey". The password for both users is "f". Signing up creates a new user. Both logging in and signing up will create a new cookie. Logging out deletes the cookie. Passwords are stored as a hash.

2.  **Friends**  
    Once the user either logs in or signs up, he/she is taken to the friends menu, which displays a table with all his/her friends. Name, group, date of last contact, desired frequency of contact, and recommended date of next contact are all displayed in the table. The table can be sorted by clicking on the header of each column.

    From this menu, the user can add a friend, add a group, edit a group, delete a group, or log out. He/she can also go to the account management menu or search for a friend to update, edit, or delete. Searching leads the user to the search menu.

3.  **Account Management**  
    The account management menu displays the username of the user and allows him/her to edit username, delete user, go back to friends menu, or log out.

4.  **Search**  
    The search menu displays the name, group, desired frequency of contact, recommended date of next contact, and entire history of contact for a single friend. It also allows the user to add a new date of last contact. There are also options to edit friend details, delete friend, go back to friends menu, or log out.

#### New Main Features Related to Go in Action 1

- **HTTP Server** - Created an HTTP server using the net/http package
- **Templates** - Makes use of HTML templates to display data. The range function is used to display data in slices.
- **POST/GET** - The POST method is used to get user-inputted data from forms, and the GET method is used to control sorting of the friend table and search for specific friends with the search function.
- **Cookies** - Cookies are created each time the user logs in or signs up and is deleted upon logging out. Each cookie is mapped to a user, so the application as a whole maintains a consistent user state while running. Only that user's information is displayed and manipulated.
- **Dependencies** - The application makes use of two non-standard packages: uuid and bcrypt. uuid is used to create unique identifiers for cookies, and bcrypt is used to hash passwords to store securely.

#### Error Handling

- **Login** - Login checks if the user exists and if the password is correct.
- **alreadyLoggedIn and getUser** - This function is used in every function that executes a template to check (using cookies) if the user is already logged in. If the user is not logged in, he/she can only access the login and signup templates. The user is automatically redirected to login.
- **Forms** - Every template that allows the user to submit data via forms has checks to make sure the appropriate fields are filled out. If they are not, the user will receive a Status Unauthorized error.
- **No duplicate users, groups, friends, etc.** - Certain fields, such as users, groups, and friends, cannot have duplicates, so if the user is creating new ones or editing existing ones, checks ensure he/she is not duplicating anything existing.
- **Friend search did not yield results** - If the search did not yield results, the user will get an error informing him/her.
