/**
  ******************************************************************************
  * @file    RSA/PKCS1v1.5_SignVerify/Src/main.c
  * @author  MCD Application Team
  * @brief   This example provides a short description of how to use the
  *          STM32 Cryptographic Library
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file in
  * the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include <string.h>
#include "main.h"
#include "cmox_crypto.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include "msg_8k.h"
#include "msg_16k.h"
#include "msg_32k.h"
#include "msg_64k.h"


static void rsa_test(uint8_t *msg, size_t msg_len, uint8_t *mod, uint8_t *sign);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);

UART_HandleTypeDef huart2;
 
/* USER CODE BEGIN 0 */
#define MOD_LEN (256U)
#define SIG_LEN (256U)
#define SHA256_OUTPUT_SIZE (32U)
cmox_rsa_key_t Rsa_Key;
cmox_rsa_handle_t Rsa_Ctx;

/* RSA working buffer */
uint8_t Working_Buffer[7000];

uint8_t Computed_Hash[SHA256_OUTPUT_SIZE] = {0};

/* USER CODE END 0 */

/* Private function prototypes -----------------------------------------------*/
static void SystemClock_Config(void);
static void Error_Handler(void);
/* Functions Definition ------------------------------------------------------*/

/**
  * @brief  Main program
  * @param  None
  * @retval None
  */
int main(void)
{

  /* STM32G0xx HAL library initialization:
       - Configure the Flash prefetch
       - Systick timer is configured by default as source of time base, but user 
         can eventually implement his proper time base source (a general purpose 
         timer for example or other time source), keeping in mind that Time base 
         duration should be kept 1ms since PPP_TIMEOUT_VALUEs are defined and 
         handled in milliseconds basis.
       - Low Level Initialization
     */
  HAL_Init();

  /* Configure the System clock */
  SystemClock_Config();

  MX_GPIO_Init();
  MX_USART2_UART_Init();
  /* Configure LED4 */
  BSP_LED_Init(LED4);

  /* Initialize cryptographic library */
  if (cmox_initialize(NULL) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }
  rsa_test((uint8_t *)msg_8k, sizeof(msg_8k), (uint8_t *)mod_8k, (uint8_t *)sig_8k);
	rsa_test((uint8_t *)msg_16k, sizeof(msg_16k), (uint8_t *)mod_16k, (uint8_t *)sig_16k);
	rsa_test((uint8_t *)msg_32k, sizeof(msg_32k), (uint8_t *)mod_32k, (uint8_t *)sig_32k);
  //rsa_test((uint8_t *)msg_64k, sizeof(msg_64k), (uint8_t *)mod_64k, (uint8_t *)sig_64k);
	

  /* Turn on LED4 in an infinite loop in case of RSA operations are successful */
  BSP_LED_On(LED4);
  while (1)
  {}
}

static void rsa_test(uint8_t *msg, size_t msg_len, uint8_t *mod, uint8_t *sign)
{
  int i;
  cmox_hash_retval_t hretval;
  cmox_rsa_retval_t retval;
  size_t computed_size;
  uint32_t fault_check = CMOX_RSA_AUTH_FAIL;

  /* --------------------------------------------------------------------------
  * USING SHA256 to generate HASH
  * --------------------------------------------------------------------------
  */
  /* Compute directly the digest passing all the needed parameters */
  hretval = cmox_hash_compute(CMOX_SHA256_ALGO,           /* Use SHA256 algorithm */
                              msg, msg_len,           /* Message to digest */
                              Computed_Hash,            /* Data buffer to receive digest data */
                              SHA256_OUTPUT_SIZE,           /* Expected digest size */
                              &computed_size);          /* Size of computed digest */
  /* Verify API returned value */
  if (hretval != CMOX_HASH_SUCCESS)
  {
    Error_Handler();
  }
  /* Verify generated data size is the expected one */
  if (computed_size != SHA256_OUTPUT_SIZE)
  {
    Error_Handler();
  }

  /* --------------------------------------------------------------------------
   * USING REGULAR PRIVATE KEY TO VERIFY
   * --------------------------------------------------------------------------
   */
  /* Construct a RSA context, specifying mathematics implementation and working buffer for later processing */
  /* Note: CMOX_RSA_MATH_FUNCS refer to the default mathematics implementation
   * selected in cmox_default_config.h. To use a specific implementation, user can
   * directly choose:
   * - CMOX_MATH_FUNCS_SMALL to select the mathematics small implementation
   * - CMOX_MATH_FUNCS_FAST to select the mathematics fast implementation
   */
  /* Compute directly the signature passing all the needed parameters */
  HAL_GPIO_WritePin(GPIOC, GPIO_PIN_8, GPIO_PIN_SET);
  cmox_rsa_construct(&Rsa_Ctx, CMOX_RSA_MATH_FUNCS, CMOX_MODEXP_PUBLIC, Working_Buffer, sizeof(Working_Buffer));

  /* Fill in RSA key structure using the public key representation */ 
  uint8_t exp=3;
  retval = cmox_rsa_setKey(&Rsa_Key,          /* RSA key structure to fill */
                           mod, 256,        /* Key modulus */
                           &exp, 1);     /* Public key exponent */
  /* Verify API returned value */
  if (retval != CMOX_RSA_SUCCESS)
  {
    Error_Handler();
  }
	retval = cmox_rsa_pkcs1v15_verify(&Rsa_Ctx,
                                    &Rsa_Key,
                                    Computed_Hash,
                                    CMOX_RSA_PKCS1V15_HASH_SHA256,
                                    sign, 256,
                                    &fault_check);
  /* Cleanup context */
  cmox_rsa_cleanup(&Rsa_Ctx);
  HAL_GPIO_WritePin(GPIOC, GPIO_PIN_8, GPIO_PIN_RESET);

  /* Verify API returned value */
  if (retval != CMOX_RSA_AUTH_SUCCESS)
  {
    Error_Handler();
  }
  /* Verify Fault check variable value */
  if (fault_check != CMOX_RSA_AUTH_SUCCESS)
  {
    Error_Handler();
  }

  /* No more need of cryptographic services, finalize cryptographic library */
  if (cmox_finalize(NULL) != CMOX_INIT_SUCCESS)
  {
    Error_Handler();
  }

}
/**
  * @brief  System Clock Configuration
  *         The system Clock is configured as follow :
  *            System Clock source            = PLL (HSI)
  *            SYSCLK(Hz)                     = 64000000
  *            HCLK(Hz)                       = 64000000
  *            AHB Prescaler                  = 1
  *            APB1 Prescaler                 = 1
  *            HSI clock division factor      = 1
  *            HSI Frequency(Hz)              = 16000000
  *            Flash Latency(WS)              = 2
  *            PLLM                           = 1
  *            PLLN                           = 8
  *            PLLP                           = 4
  *            PLLQ                           = 2
  *            PLLR                           = 2
  * @param  None
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSIDiv = RCC_HSI_DIV1;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = RCC_PLLM_DIV1;
  RCC_OscInitStruct.PLL.PLLN = 8;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV2;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
}
/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  huart2.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart2.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart2.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart2, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart2, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOF_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOC, GPIO_PIN_8, GPIO_PIN_RESET);

  /*Configure GPIO pin : LED_GREEN_Pin */
  GPIO_InitStruct.Pin = LED_GREEN_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
  HAL_GPIO_Init(LED_GREEN_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PC8 */
  GPIO_InitStruct.Pin = GPIO_PIN_8;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */


/**
  * @brief  This function is executed in case of error occurrence
  * @param  None
  * @retval None
  */
static void Error_Handler(void)
{
  /* User may add here some code to deal with this error */
  /* Toggle LED4 @2Hz to notify error condition */
  while (1)
  {
    BSP_LED_Toggle(LED4);
    HAL_Delay(250);
  }
}

#ifdef USE_FULL_ASSERT

/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */

  /* Infinite loop */
  while (1)
  {}
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
