package io.bdemers.example.okta;

import com.okta.sdk.client.Client;
import com.okta.sdk.resource.ResourceException;
import com.okta.sdk.resource.group.Group;
import com.okta.sdk.resource.user.ChangePasswordRequest;
import com.okta.sdk.resource.user.PasswordCredential;
import com.okta.sdk.resource.user.User;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Controller
public class BasicController {

    private final Client client;

    public BasicController(Client client) {
        this.client = client;
    }

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/profile")
    public ModelAndView userDetails(OAuth2AuthenticationToken authentication) {

        Map<String, Object> data = new HashMap<>();
        data.put("details", authentication.getPrincipal().getAttributes());
        data.put("groups", authentication.getPrincipal().getAttributes().get("groups"));

        return new ModelAndView("userProfile", data);
    }

    @GetMapping("/user")
    public ModelAndView userInfo(OAuth2AuthenticationToken authentication) {

        User user = client.getUser(authentication.getName());

        Map<String, Object> data = new HashMap<>();
        data.put("user", SimpleUser.from(user));
        data.put("groups", user.listGroups().stream()
                .map(group -> group.getProfile().getName())
                .collect(Collectors.toList()));

        return new ModelAndView("userInfo", data);
    }

    @PostMapping("/user")
    public ModelAndView updateUser(SimpleUser simpleUser) {

        // get user
        User user = client.getUser(simpleUser.getId());
        user.getProfile()
                .setEmail(simpleUser.getEmail())
                .setFirstName(simpleUser.getFirstName())
                .setLastName(simpleUser.getLastName());
        user.update();

        Map<String, Object> data = new HashMap<>();
        data.put("user", SimpleUser.from(user));

        return new ModelAndView("userInfo", data);
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('Admin')")
    public ModelAndView admin() {
        return new ModelAndView("userToGroup", Collections.singletonMap("userToGroup", new UserToGroup()));
    }

    @PostMapping("/admin")
    @PreAuthorize("hasAuthority('Admin')")
    public ModelAndView admin(UserToGroup userToGroup) {

        // Need to search for the group name, this is ugly
        Group group = client.listGroups(userToGroup.groupName, null).single();

        client.getUser(userToGroup.getEmail())
                .addToGroup(group.getId());

        return new ModelAndView("userToGroup", Collections.singletonMap("userToGroup", new UserToGroup()));
    }

    @GetMapping("/password")
    public ModelAndView password() {
        return new ModelAndView("changePassword", Collections.singletonMap("password", new PasswordRequest()));
    }

    @PostMapping("/password")
    public ModelAndView password(PasswordRequest passwordRequest, OAuth2AuthenticationToken authentication) {

        PasswordRequest request = new PasswordRequest();
        try {
            User user = client.getUser(authentication.getName());
            user.changePassword(client.instantiate(ChangePasswordRequest.class)
                    .setNewPassword(client.instantiate(PasswordCredential.class)
                            .setValue(passwordRequest.password.toCharArray()))
                    .setOldPassword(client.instantiate(PasswordCredential.class)
                            .setValue(passwordRequest.oldPassword.toCharArray())));

        } catch (ResourceException e) {
            // this is ugly, use spring built in logic for this instead
            request.setError(e.getMessage());
        }

        return new ModelAndView("changePassword", Collections.singletonMap("password", request));
    }

    static class UserToGroup {
        private String email;
        private String groupName;

        public String getEmail() {
            return email;
        }

        public UserToGroup setEmail(String email) {
            this.email = email;
            return this;
        }

        public String getGroupName() {
            return groupName;
        }

        public UserToGroup setGroupName(String groupName) {
            this.groupName = groupName;
            return this;
        }
    }

    static class SimpleUser {
        private String id;
        private String email;
        private String firstName;
        private String lastName;

        public String getId() {
            return id;
        }

        public SimpleUser setId(String id) {
            this.id = id;
            return this;
        }

        public String getEmail() {
            return email;
        }

        public SimpleUser setEmail(String email) {
            this.email = email;
            return this;
        }

        public String getFirstName() {
            return firstName;
        }

        public SimpleUser setFirstName(String firstName) {
            this.firstName = firstName;
            return this;
        }

        public String getLastName() {
            return lastName;
        }

        public SimpleUser setLastName(String lastName) {
            this.lastName = lastName;
            return this;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            SimpleUser that = (SimpleUser) o;
            return Objects.equals(id, that.id) &&
                   Objects.equals(email, that.email) &&
                   Objects.equals(firstName, that.firstName) &&
                   Objects.equals(lastName, that.lastName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, email, firstName, lastName);
        }

        static SimpleUser from(User user) {
            return new SimpleUser()
                    .setId(user.getId())
                    .setEmail(user.getProfile().getEmail())
                    .setFirstName(user.getProfile().getFirstName())
                    .setLastName(user.getProfile().getLastName());
        }
    }

    static class PasswordRequest {
        private String password;
        private String oldPassword;
        private String error;

        public String getPassword() {
            return password;
        }

        public PasswordRequest setPassword(String password) {
            this.password = password;
            return this;
        }

        public String getOldPassword() {
            return oldPassword;
        }

        public PasswordRequest setOldPassword(String oldPassword) {
            this.oldPassword = oldPassword;
            return this;
        }

        public String getError() {
            return error;
        }

        public PasswordRequest setError(String error) {
            this.error = error;
            return this;
        }
    }
}
