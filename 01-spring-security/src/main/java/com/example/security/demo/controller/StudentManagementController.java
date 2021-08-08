package com.example.security.demo.controller;

import com.example.security.demo.model.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/management/api/v1/students/")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(new Student(1, "James Bond"),
            new Student(2, "Maria Jones"), new Student(3, "Anna Smith"));

    /*
    * USING PERMISSION-BASED AUTHORIZATION ON METHOD LEVEL -> THE SAME AS IN SecurityConfig
    * hasRole
    * hasAnyRole
    * hasAuthority
    * hasAnyAuthority
    * */
    @PreAuthorize("hasAuthority('student:write')")
    @PostMapping
    public void addStudent(@RequestBody Student student) {
        System.out.println(String.format("Adding a student = %s",student));
    }

    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMIN_TRAINEE')")
    @GetMapping
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PreAuthorize("hasAuthority('student:write')")
    @PutMapping("{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId, Student student) {
        System.out.println(String.format("Student id: %s, new data: %s", studentId, student));
    }

    @PreAuthorize("hasAuthority('student:write')")
    @DeleteMapping("{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println(String.format("Deleting a student => student id = %d",studentId));
    }


}
