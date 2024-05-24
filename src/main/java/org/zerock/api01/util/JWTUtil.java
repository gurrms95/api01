package org.zerock.api01.util;

import io.jsonwebtoken.JwtException;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
@Log4j2
public class JWTUtil {

    @Value("${org.zerock.jwt.secret}")
    private String key;

    public String generateToken(Map<String,Object> valueMap, int days){
        log.info("generateKey..."+ key);

        //헤더부분
        Map<String,Object> hedaer = new HashMap<>();
        hedaer.put("typ","JWT");
        hedaer.put("alg","HS256");

        //payLoad 부분설정
        Map<String,Object> payLoad = new HashMap<>();
        payLoad.putAll(valueMap);

        //테스트시에는 짧은 유효기간
        int time = (60*24) * days; //테스트는 분단위로 나중에  60*24(일) 단위 변경

        String jwtStr = Jwts.builder()
                .setHeader(hedaer)
                .setClaims(payLoad)
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant()))
                .signWith(SignatureAlgorithm.HS256,key.getBytes())
                .compact();

        return jwtStr;
    }

    public Map<String, Object> validateToken(String token) throws JwtException{
        Map<String,Object> claim = null;

        claim = Jwts.parser()
                .setSigningKey(key.getBytes())
                .parseClaimsJwt(token)
                .getBody();

        return claim;
    }
}
