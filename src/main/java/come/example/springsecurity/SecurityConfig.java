package come.example.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // This is required to allow method based access toggle
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

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
        UserDetails user1 = User.withUsername("user1").password(passwordEncoderFunction().encode("pass1")).roles("USER").build();
        UserDetails user2 = User.withUsername("user2").password(passwordEncoderFunction().encode("pass2")).roles("USER").build();
        UserDetails admin = User.withUsername("admin").password(passwordEncoderFunction().encode("adminPass")).roles("ADMIN").build();

        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(user2);
        userDetailsManager.createUser(admin);

        return userDetailsManager;
    }

    @Bean
    public PasswordEncoder passwordEncoderFunction(){
        return new BCryptPasswordEncoder();
    }
}
