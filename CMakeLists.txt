# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)


include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(https_server)

# This example uses an extra component for common functions such as button and wifi connect
# set(EXTRA_COMPONENT_DIRS ../web_common_components/button ../web_common_components/web_wifi)
