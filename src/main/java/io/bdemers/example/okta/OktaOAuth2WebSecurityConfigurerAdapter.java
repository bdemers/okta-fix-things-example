package io.bdemers.example.okta;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
class OktaOAuth2WebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            // Require authentication for all requests under /api/private
            .antMatchers("/profile/**").authenticated()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/password/**").authenticated()
                .antMatchers("/admin/**").authenticated()
            // enable OAuth2/OIDC
            .and()
                .oauth2Login();
    }
}