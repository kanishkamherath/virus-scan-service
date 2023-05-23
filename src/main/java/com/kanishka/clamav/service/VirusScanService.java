package com.kanishka.clamav.service;

import org.springframework.web.multipart.MultipartFile;
import com.kanishka.clamav.dto.VirusScanResult;

public interface VirusScanService {

  VirusScanResult virusScan(MultipartFile file);

}
