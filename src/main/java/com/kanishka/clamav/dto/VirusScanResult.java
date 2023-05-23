package com.kanishka.clamav.dto;

import org.springframework.util.StringUtils;
import com.kanishka.clamav.enums.VirusScanStatus;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VirusScanResult {

  private VirusScanStatus status;
  private String result;
  private String signature;

  public VirusScanResult() {
    super();
  }

  public VirusScanResult(VirusScanStatus status, String result) {
    super();
    this.status = status;
    this.result = result;
  }

  public VirusScanResult(VirusScanStatus status, String result, String signature) {
    super();
    this.status = status;
    this.result = result;
    this.signature = signature;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("Status: ");
    sb.append(getStatus());
    sb.append(System.lineSeparator());

    if (StringUtils.hasText(getResult())) {
      sb.append("Result: ");
      sb.append(getResult());
      sb.append(System.lineSeparator());
    }

    if (StringUtils.hasText(getSignature())) {
      sb.append("Signature: ");
      sb.append(getSignature());
      sb.append(System.lineSeparator());
    }

    return sb.toString();
  }
}
