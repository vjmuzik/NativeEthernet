//In Serial monitor make sure a line ending with carriage return is selected

#include <NativeEthernet.h>

void help_cmd(fnet_shell_desc_t desc, fnet_index_t argc, fnet_char_t **argv);
void mkdir_cmd(fnet_shell_desc_t desc, fnet_index_t argc, fnet_char_t **argv);

static const fnet_shell_command_t teensy_cmd_table [] = {
  {"?", 0, 0, help_cmd,"Display this help message.", ""},
  {"help", 0, 0, help_cmd,"Display this help message.", ""},
  {"mkdir", 1, 1, mkdir_cmd,      "Make directory", "<dir name>"},
  {0, 0, 0, 0, 0, 0},
};

fnet_shell_t teensy_shell = {
  teensy_cmd_table,
  "PROMT> ",
  0,
};

fnet_shell_desc_t shell_desc = 0; // Shell descriptor.
fnet_char_t cmd_line_buffer[64] = {0};

void setup() {
  while(!Serial);
}

void loop() {
  fnet_shell_params_t shell_params;
  shell_params.shell = &teensy_shell;
  shell_params.cmd_line_buffer = cmd_line_buffer;
  shell_params.cmd_line_buffer_size = sizeof(cmd_line_buffer);
  shell_params.stream = FNET_SERIAL_STREAM_DEFAULT; // Use default stream.
  shell_params.echo = FNET_TRUE; // Enable echo.
  if((shell_desc = fnet_shell_init(&shell_params)) != 0)
  {
      fnet_printf("\n Shell started.\n");
      while(1)
      {
          fnet_service_poll();
      }
   }
   else
   {
       fnet_printf("\n Shell initialization is failed.\n");
   }
}

void help_cmd(fnet_shell_desc_t desc, fnet_index_t argc, fnet_char_t **argv ){
  fnet_shell_help(desc);
}

void mkdir_cmd(fnet_shell_desc_t desc, fnet_index_t argc, fnet_char_t **argv ){
  Serial.print("Directory \"");
  Serial.print(argv[1]);
  Serial.print("\" created!\n");
}
