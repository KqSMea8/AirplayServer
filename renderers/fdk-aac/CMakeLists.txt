cmake_minimum_required(VERSION 3.4.1)

set(fdk_aac_path .)

aux_source_directory(${fdk_aac_path}/libAACdec/src fdk_aac_dec_src)
aux_source_directory(${fdk_aac_path}/libAACenc/src fdk_aac_enc_src)
aux_source_directory(${fdk_aac_path}/libPCMutils/src fdk_aac_pcm_utils_src)
aux_source_directory(${fdk_aac_path}/libFDK/src fdk_aac_fdk_src)
aux_source_directory(${fdk_aac_path}/libSYS/src fdk_aac_sys_src)
aux_source_directory(${fdk_aac_path}/libMpegTPDec/src fdk_aac_mpeg_tp_dec_src)
aux_source_directory(${fdk_aac_path}/libMpegTPEnc/src fdk_aac_mpeg_tp_enc_src)
aux_source_directory(${fdk_aac_path}/libSBRdec/src fdk_aac_sbr_dec_src)
aux_source_directory(${fdk_aac_path}/libSBRenc/src fdk_aac_sbr_enc_src)

aux_source_directory(${fdk_aac_path}/libArithCoding/src fdk_aac_arith_coding_src)
aux_source_directory(${fdk_aac_path}/libDRCdec/src fdk_aac_drc_dec_src)
aux_source_directory(${fdk_aac_path}/libSACdec/src fdk_aac_sac_dec_src)
aux_source_directory(${fdk_aac_path}/libSACenc/src fdk_aac_sac_enc_src)

add_library(fdk-aac
        STATIC
  ${fdk_aac_dec_src}
  ${fdk_aac_enc_src}
  ${fdk_aac_pcm_utils_src}
  ${fdk_aac_fdk_src}
  ${fdk_aac_sys_src}
  ${fdk_aac_mpeg_tp_dec_src}
  ${fdk_aac_mpeg_tp_enc_src}
  ${fdk_aac_sbr_dec_src}
        ${fdk_aac_sbr_enc_src}

        ${fdk_aac_arith_coding_src}
        ${fdk_aac_drc_dec_src}
        ${fdk_aac_sac_dec_src}
        ${fdk_aac_sac_enc_src}
  )

target_include_directories(fdk-aac
  PRIVATE
  ${fdk_aac_path}/libAACdec/include
  ${fdk_aac_path}/libAACenc/include
  ${fdk_aac_path}/libPCMutils/include
  ${fdk_aac_path}/libFDK/include
  ${fdk_aac_path}/libSYS/include
  ${fdk_aac_path}/libMpegTPDec/include
  ${fdk_aac_path}/libMpegTPEnc/include
  ${fdk_aac_path}/libSBRdec/include
  ${fdk_aac_path}/libSBRenc/include
${fdk_aac_path}/libArithCoding/include
${fdk_aac_path}/libDRCdec/include
${fdk_aac_path}/libSACdec/include
${fdk_aac_path}/libSACenc/include
  )
