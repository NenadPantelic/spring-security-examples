package com.example.security.demo.controller;

import com.example.security.demo.model.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;


/*
* With basic auth, we need to provide username and password in header (encoded as Base64) with every request.
* */
@RestController
@RequestMapping("/api/v1/students/")
public class StudentController {
    private static final List<Student> students = Arrays.asList(new Student(1, "James Bond"),
            new Student(2, "Maria Jones"), new Student(3, "Anna Smith"));

    @GetMapping("{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId) {
        return students
                .stream()
                .filter(student -> student.getId().equals(studentId))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        String.format("Student with the id = %d doesn't exist!", studentId)));
    }

}
