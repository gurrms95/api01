package org.zerock.api01.util;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

@SpringBootTest
@Log4j2
public class JWTUtilTest {

    @Autowired
    private JWTUtil jwtUtil;

    @Test
    private void testGenerate(){
        Map<String ,Object> claimMap = Map.of("mid","ABCD");
        String jwtStr = jwtUtil.generateToken(claimMap,1);

        log.info(jwtStr);
    }
}
