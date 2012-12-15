from setuptools import setup
import os

data_files = []

image_files = []
doc_files = []
gtk_doc_files = []
for afile in os.listdir('doc'):
    #doc_files.append('doc/' + afile)
    if afile != '.svn':
        doc_files.append('doc/' + afile)
for afile in os.listdir('gtk/docs'):
    #gtk_doc_files.append('gtk/docs/' + afile)
    if afile != '.svn':
        gtk_doc_files.append('gtk/docs/' + afile)

data_files = ['gtk/images/world.png', 'gtk/images/xsser.jpg',
              'gtk/images/xssericon_16x16.png',
              'gtk/images/xssericon_24x24.png']
gtk_files = ['gtk/xsser.ui']
gtk_app_files = ['gtk/xsser.desktop']

setup(
    name = "xsser",
    version = "1.6",
    packages = ['XSSer', 'XSSer.fuzzing', 'XSSer.post'],
    data_files = [('/usr/share/doc/xsser/', doc_files), 
                  ('/usr/share/xsser/gtk/images/', data_files),
                  ('/usr/share/xsser/gtk/docs/', gtk_doc_files),
                  ('/usr/share/applications/', gtk_app_files),
                  ('/usr/share/xsser/gtk/', gtk_files)],
    scripts = ['xsser'],
    test_suite = "tests"
)



