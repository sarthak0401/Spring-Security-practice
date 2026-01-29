package come.example.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // This is required to allow method based access toggle
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.authorizeHttpRequests(auth -> auth.requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated())
                // .formLogin(Customizer.withDefaults()) ;
                .httpBasic(Customizer.withDefaults());

        http.headers(headers -> headers.frameOptions(frame -> frame.disable()));
        http.csrf(csrf -> csrf.disable());

        return http.build();
    }


    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.withUsername("user1").password("{noop}pass1").roles("USER").build();
        UserDetails user2 = User.withUsername("user2").password("{noop}pass2").roles("USER").build();
        UserDetails admin = User.withUsername("admin").password("{noop}adminPass").roles("ADMIN").build();


        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager();

        return new InMemoryUserDetailsManager(user1, user2, admin);
    }
}
