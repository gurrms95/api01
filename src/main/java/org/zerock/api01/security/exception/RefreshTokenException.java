package org.zerock.api01.security.exception;

import com.google.gson.Gson;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

public class RefreshTokenException extends RuntimeException{
    private ErrorCase errorCase;

    public enum ErrorCase{
        NO_ACCESS, BAD_ACCESS, NO_REFRESH, OLD_REFRESH, BAD_REFRESH
    }

    public RefreshTokenException(ErrorCase erroCase){
        super(erroCase.name());
        this.errorCase = erroCase;
    }


    public void sendResponseError(HttpServletResponse response){
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Gson gson = new Gson();

        String responseStr = gson.toJson(Map.of("msg",errorCase.name(),"time",new Date()));

        try {
            response.getWriter().println(responseStr);
        } catch (IOException e){
            throw new RuntimeException(e);
        }
    }
}
