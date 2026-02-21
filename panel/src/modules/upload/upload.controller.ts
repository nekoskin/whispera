import {
  Controller,
  Post,
  UseInterceptors,
  UploadedFile,
  BadRequestException,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';

@Controller('api/upload')
export class UploadController {
  @Post()
  @UseInterceptors(
    FileInterceptor('file', {
      storage: diskStorage({
        destination: './public/uploads',
        filename: (req, file, cb) => {
          const randomName = Array(32)
            .fill(null)
            .map(() => Math.round(Math.random() * 16).toString(16))
            .join('');
          cb(null, `${randomName}${extname(file.originalname)}`);
        },
      }),
      limits: {
        fileSize: 50 * 1024 * 1024, // 50MB
      },
      fileFilter: (req, file, cb) => {
        if (!file.mimetype.match(/\/(jpg|jpeg|png|gif|mp4|webm)$/)) {
          return cb(new BadRequestException('Only image or video files are allowed!'), false);
        }
        cb(null, true);
      },
    }),
  )
  uploadFile(@UploadedFile() file: Express.Multer.File) {
    console.log('Upload request received');
    if (!file) {
      console.error('File is missing');
      throw new BadRequestException('File is required');
    }
    console.log('File uploaded successfully:', file.filename);
    return {
      url: `/uploads/${file.filename}`,
      type: file.mimetype.startsWith('video') ? 'video' : 'image',
    };
  }
}
