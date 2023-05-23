package com.kanishka.clamav.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import com.kanishka.clamav.dto.VirusScanResult;
import com.kanishka.clamav.service.VirusScanService;

@Controller
public class FileUploadController {

  @Autowired
  private VirusScanService virusScanService;

  @GetMapping("/index")
  public String home() {
    return "index";
  }

  @PostMapping("/upload")
  public ResponseEntity<VirusScanResult> handleFileUpload(
      @RequestParam("file") MultipartFile file) {

    return ResponseEntity.ok(virusScanService.virusScan(file));
  }

}
